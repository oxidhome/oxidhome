//! Tensor shape and size limits for `inference`.
//!
//! The host runs these checks on every `named-tensor` a plugin passes to
//! `model.infer` **and** on every tensor a model returns, before copying
//! it into the guest. All arithmetic is overflow-checked: a shape whose
//! element count overflows `u64` is rejected, never wrapped into range.

/// Most dimensions a tensor may have.
pub const MAX_TENSOR_RANK: usize = 8;
/// Most elements in one tensor (2^26).
pub const MAX_TENSOR_ELEMENTS: u64 = 1 << 26;
/// Most bytes in one tensor (64 MiB).
pub const MAX_TENSOR_BYTES: u64 = 64 << 20;
/// Most tensors in one `infer` call (inputs, or outputs).
pub const MAX_TENSORS_PER_CALL: usize = 16;
/// Most tensor bytes in one `infer` call (256 MiB).
pub const MAX_CALL_BYTES: u64 = 256 << 20;

/// Element type, mirroring WIT `tensor-dtype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementType {
    F32,
    F16,
    I8,
    U8,
    I32,
    I64,
}

impl ElementType {
    /// Width of one element in bytes.
    #[must_use]
    pub const fn width(self) -> u64 {
        match self {
            Self::I8 | Self::U8 => 1,
            Self::F16 => 2,
            Self::F32 | Self::I32 => 4,
            Self::I64 => 8,
        }
    }
}

/// One dimension of a model's declared shape, mirroring WIT `tensor-dim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DimSpec {
    Fixed(u32),
    Dynamic,
}

/// Why a tensor or tensor set was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TensorError {
    #[error("tensor rank {0} exceeds {MAX_TENSOR_RANK}")]
    RankTooHigh(usize),
    #[error("tensor dimension {index} is 0")]
    ZeroDim { index: usize },
    #[error("tensor has more than {MAX_TENSOR_ELEMENTS} elements")]
    TooManyElements,
    #[error("tensor is larger than {MAX_TENSOR_BYTES} bytes")]
    TooLarge,
    #[error("tensor data is {actual} bytes, shape and dtype need {expected}")]
    DataLength { expected: u64, actual: u64 },
    #[error("tensor rank {actual} does not match the model's {expected}")]
    RankMismatch { expected: usize, actual: usize },
    #[error("tensor dimension {index} is {actual}, the model fixes it at {expected}")]
    DimMismatch {
        index: usize,
        expected: u32,
        actual: u32,
    },
    #[error("call passes {0} tensors; at most {MAX_TENSORS_PER_CALL} allowed")]
    TooManyTensors(usize),
    #[error("call passes more than {MAX_CALL_BYTES} bytes of tensor data")]
    CallTooLarge,
}

/// Check a shape's rank and dimensions and return the byte length a tensor
/// of that shape and element type must have.
pub fn byte_len(shape: &[u32], dtype: ElementType) -> Result<u64, TensorError> {
    if shape.len() > MAX_TENSOR_RANK {
        return Err(TensorError::RankTooHigh(shape.len()));
    }
    let mut elements: u64 = 1;
    for (index, &dim) in shape.iter().enumerate() {
        if dim == 0 {
            return Err(TensorError::ZeroDim { index });
        }
        elements = elements
            .checked_mul(u64::from(dim))
            .filter(|&n| n <= MAX_TENSOR_ELEMENTS)
            .ok_or(TensorError::TooManyElements)?;
    }
    // Can't overflow (2^26 × 8), but keep the arithmetic checked anyway.
    elements
        .checked_mul(dtype.width())
        .filter(|&n| n <= MAX_TENSOR_BYTES)
        .ok_or(TensorError::TooLarge)
}

/// Check one tensor: shape limits, then that `data_len` is exactly what
/// the shape and element type need. Returns the byte length.
pub fn validate_tensor(
    shape: &[u32],
    dtype: ElementType,
    data_len: usize,
) -> Result<u64, TensorError> {
    let expected = byte_len(shape, dtype)?;
    // `usize` → `u64` is lossless on every target the host supports;
    // saturate rather than wrap if that ever stops being true.
    let actual = u64::try_from(data_len).unwrap_or(u64::MAX);
    if actual == expected {
        Ok(expected)
    } else {
        Err(TensorError::DataLength { expected, actual })
    }
}

/// Check a concrete shape against the model's declared shape: same rank,
/// and every fixed dimension matches exactly.
pub fn validate_shape_against_spec(spec: &[DimSpec], shape: &[u32]) -> Result<(), TensorError> {
    if spec.len() != shape.len() {
        return Err(TensorError::RankMismatch {
            expected: spec.len(),
            actual: shape.len(),
        });
    }
    for (index, (dim_spec, &actual)) in spec.iter().zip(shape).enumerate() {
        if let DimSpec::Fixed(expected) = *dim_spec
            && expected != actual
        {
            return Err(TensorError::DimMismatch {
                index,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

/// One tensor of an `infer` call, as [`validate_call`] sees it.
#[derive(Debug, Clone, Copy)]
pub struct TensorRef<'a> {
    pub shape: &'a [u32],
    pub dtype: ElementType,
    pub data_len: usize,
}

/// Check every tensor of one `infer` call (inputs or outputs) and the
/// per-call count and byte totals. Returns the total bytes.
pub fn validate_call<'a>(
    tensors: impl ExactSizeIterator<Item = TensorRef<'a>>,
) -> Result<u64, TensorError> {
    if tensors.len() > MAX_TENSORS_PER_CALL {
        return Err(TensorError::TooManyTensors(tensors.len()));
    }
    let mut total: u64 = 0;
    for t in tensors {
        let bytes = validate_tensor(t.shape, t.dtype, t.data_len)?;
        total = total
            .checked_add(bytes)
            .filter(|&n| n <= MAX_CALL_BYTES)
            .ok_or(TensorError::CallTooLarge)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_len_multiplies_shape_and_width() {
        assert_eq!(byte_len(&[1, 3, 640, 640], ElementType::F32), Ok(4_915_200));
        assert_eq!(byte_len(&[10], ElementType::I64), Ok(80));
        assert_eq!(byte_len(&[7], ElementType::U8), Ok(7));
        assert_eq!(byte_len(&[2, 2], ElementType::F16), Ok(8));
        // Rank 0 is a scalar: one element.
        assert_eq!(byte_len(&[], ElementType::I32), Ok(4));
    }

    #[test]
    fn rejects_rank_and_zero_dims() {
        assert_eq!(
            byte_len(&[1; MAX_TENSOR_RANK + 1], ElementType::U8),
            Err(TensorError::RankTooHigh(MAX_TENSOR_RANK + 1))
        );
        assert_eq!(byte_len(&[1; MAX_TENSOR_RANK], ElementType::U8), Ok(1));
        assert_eq!(
            byte_len(&[4, 0, 4], ElementType::U8),
            Err(TensorError::ZeroDim { index: 1 })
        );
    }

    #[test]
    fn element_and_byte_limits_are_overflow_safe() {
        // 2^32-1 per dim × 8 dims overflows u64 many times over.
        assert_eq!(
            byte_len(&[u32::MAX; MAX_TENSOR_RANK], ElementType::U8),
            Err(TensorError::TooManyElements)
        );
        // Product that wraps to a small value in u32/u64 arithmetic.
        assert_eq!(
            byte_len(&[1 << 16, 1 << 16, 1 << 16, 1 << 16], ElementType::U8),
            Err(TensorError::TooManyElements)
        );
        // Exactly at the element limit is fine for u8 …
        let at_limit = [1 << 13, 1 << 13];
        assert_eq!(
            byte_len(&at_limit, ElementType::U8),
            Ok(MAX_TENSOR_ELEMENTS)
        );
        // … one more element isn't.
        assert_eq!(
            byte_len(&[(1 << 26) + 1], ElementType::U8),
            Err(TensorError::TooManyElements)
        );
        // 2^26 f32 elements = 256 MiB > 64 MiB.
        assert_eq!(
            byte_len(&at_limit, ElementType::F32),
            Err(TensorError::TooLarge)
        );
        // 2^24 f32 elements = exactly 64 MiB.
        assert_eq!(
            byte_len(&[1 << 12, 1 << 12], ElementType::F32),
            Ok(MAX_TENSOR_BYTES)
        );
    }

    #[test]
    fn data_length_must_match_exactly() {
        assert_eq!(validate_tensor(&[2, 3], ElementType::F32, 24), Ok(24));
        for len in [0, 23, 25, usize::MAX] {
            assert!(
                matches!(
                    validate_tensor(&[2, 3], ElementType::F32, len),
                    Err(TensorError::DataLength { expected: 24, .. })
                ),
                "{len}"
            );
        }
    }

    #[test]
    fn shape_against_spec() {
        let spec = [DimSpec::Dynamic, DimSpec::Fixed(3), DimSpec::Fixed(224)];
        assert_eq!(validate_shape_against_spec(&spec, &[8, 3, 224]), Ok(()));
        assert_eq!(
            validate_shape_against_spec(&spec, &[8, 3]),
            Err(TensorError::RankMismatch {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            validate_shape_against_spec(&spec, &[8, 4, 224]),
            Err(TensorError::DimMismatch {
                index: 1,
                expected: 3,
                actual: 4
            })
        );
    }

    #[test]
    fn call_limits() {
        let shape = [1 << 12, 1 << 12];
        let big = TensorRef {
            shape: &shape,
            dtype: ElementType::F32,
            data_len: 64 << 20,
        };
        assert_eq!(validate_call([big; 4].into_iter()), Ok(MAX_CALL_BYTES));
        assert_eq!(
            validate_call([big; 5].into_iter()),
            Err(TensorError::CallTooLarge)
        );
        let small = TensorRef {
            shape: &[1],
            dtype: ElementType::U8,
            data_len: 1,
        };
        assert_eq!(
            validate_call([small; MAX_TENSORS_PER_CALL].into_iter()),
            Ok(16)
        );
        assert_eq!(
            validate_call([small; MAX_TENSORS_PER_CALL + 1].into_iter()),
            Err(TensorError::TooManyTensors(MAX_TENSORS_PER_CALL + 1))
        );
        let bad = TensorRef {
            data_len: 2,
            ..small
        };
        assert!(matches!(
            validate_call([small, bad].into_iter()),
            Err(TensorError::DataLength { .. })
        ));
        assert_eq!(validate_call(std::iter::empty()), Ok(0));
    }
}
