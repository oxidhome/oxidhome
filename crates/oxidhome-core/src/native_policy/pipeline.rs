//! Numeric bounds on a `media-pipeline` that the WIT documents.

/// Most `steps` in one `media-pipeline`.
pub const MAX_PIPELINE_STEPS: usize = 32;
/// Most `sinks` in one `media-pipeline`.
pub const MAX_PIPELINE_SINKS: usize = 8;
/// Largest width or height of a `frame-size` / `crop-rect`.
pub const MAX_FRAME_DIMENSION: u32 = 8192;
/// Highest `max-framerate` filter value or inference-tap `fps`.
pub const MAX_FRAMERATE: f32 = 120.0;

/// Why a pipeline bound was violated.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PipelineError {
    #[error("pipeline has {0} steps; at most {MAX_PIPELINE_STEPS} allowed")]
    TooManySteps(usize),
    #[error("pipeline has {0} sinks; at most {MAX_PIPELINE_SINKS} allowed")]
    TooManySinks(usize),
    #[error("frame size {width}x{height} is outside 1..={MAX_FRAME_DIMENSION} per side")]
    FrameSize { width: u32, height: u32 },
    #[error("crop rectangle does not fit inside the {frame_width}x{frame_height} frame")]
    CropOutOfBounds { frame_width: u32, frame_height: u32 },
    #[error("frame rate {0} is not finite and in (0, {MAX_FRAMERATE}]")]
    Framerate(f32),
}

/// Check the step and sink counts of a pipeline.
pub fn validate_pipeline_size(steps: usize, sinks: usize) -> Result<(), PipelineError> {
    if steps > MAX_PIPELINE_STEPS {
        return Err(PipelineError::TooManySteps(steps));
    }
    if sinks > MAX_PIPELINE_SINKS {
        return Err(PipelineError::TooManySinks(sinks));
    }
    Ok(())
}

/// Check a `frame-size` (scale, resize, letterbox targets).
pub fn validate_frame_size(width: u32, height: u32) -> Result<(), PipelineError> {
    let ok = |d: u32| (1..=MAX_FRAME_DIMENSION).contains(&d);
    if ok(width) && ok(height) {
        Ok(())
    } else {
        Err(PipelineError::FrameSize { width, height })
    }
}

/// Check a `crop-rect` against the frame it applies to. The arithmetic is
/// overflow-checked, so `x = u32::MAX` can't wrap into range.
pub fn validate_crop(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    frame_width: u32,
    frame_height: u32,
) -> Result<(), PipelineError> {
    validate_frame_size(width, height)?;
    let fits = |off: u32, len: u32, max: u32| off.checked_add(len).is_some_and(|end| end <= max);
    if fits(x, width, frame_width) && fits(y, height, frame_height) {
        Ok(())
    } else {
        Err(PipelineError::CropOutOfBounds {
            frame_width,
            frame_height,
        })
    }
}

/// Check a frame rate (`max-framerate`, inference-tap `fps`).
pub fn validate_framerate(fps: f32) -> Result<(), PipelineError> {
    if fps.is_finite() && fps > 0.0 && fps <= MAX_FRAMERATE {
        Ok(())
    } else {
        Err(PipelineError::Framerate(fps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_size() {
        assert_eq!(
            validate_pipeline_size(MAX_PIPELINE_STEPS, MAX_PIPELINE_SINKS),
            Ok(())
        );
        assert_eq!(
            validate_pipeline_size(MAX_PIPELINE_STEPS + 1, 0),
            Err(PipelineError::TooManySteps(MAX_PIPELINE_STEPS + 1))
        );
        assert_eq!(
            validate_pipeline_size(0, MAX_PIPELINE_SINKS + 1),
            Err(PipelineError::TooManySinks(MAX_PIPELINE_SINKS + 1))
        );
    }

    #[test]
    fn frame_size() {
        assert_eq!(validate_frame_size(1, 1), Ok(()));
        assert_eq!(
            validate_frame_size(MAX_FRAME_DIMENSION, MAX_FRAME_DIMENSION),
            Ok(())
        );
        for (w, h) in [
            (0, 10),
            (10, 0),
            (MAX_FRAME_DIMENSION + 1, 10),
            (u32::MAX, 1),
        ] {
            assert_eq!(
                validate_frame_size(w, h),
                Err(PipelineError::FrameSize {
                    width: w,
                    height: h
                })
            );
        }
    }

    #[test]
    fn crop() {
        assert_eq!(validate_crop(0, 0, 1920, 1080, 1920, 1080), Ok(()));
        assert_eq!(validate_crop(100, 50, 640, 360, 1920, 1080), Ok(()));
        let oob = Err(PipelineError::CropOutOfBounds {
            frame_width: 1920,
            frame_height: 1080,
        });
        assert_eq!(validate_crop(1, 0, 1920, 1080, 1920, 1080), oob);
        assert_eq!(validate_crop(0, 1080, 10, 1, 1920, 1080), oob);
        assert_eq!(validate_crop(u32::MAX, 0, 10, 10, 1920, 1080), oob);
        assert_eq!(validate_crop(0, u32::MAX, 10, 10, 1920, 1080), oob);
        assert!(matches!(
            validate_crop(0, 0, 0, 10, 1920, 1080),
            Err(PipelineError::FrameSize { .. })
        ));
    }

    #[test]
    fn framerate() {
        for fps in [0.1, 1.0, 30.0, MAX_FRAMERATE] {
            assert_eq!(validate_framerate(fps), Ok(()), "{fps}");
        }
        for fps in [0.0, -1.0, MAX_FRAMERATE + 0.5, f32::NAN, f32::INFINITY] {
            assert!(validate_framerate(fps).is_err(), "{fps}");
        }
    }
}
