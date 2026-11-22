//! Numeric bounds on a `media-pipeline` that the WIT documents.

use std::ops::RangeInclusive;

/// Most `steps` in one `media-pipeline`.
pub const MAX_PIPELINE_STEPS: usize = 32;
/// Most `sinks` in one `media-pipeline`.
pub const MAX_PIPELINE_SINKS: usize = 8;
/// Most `preprocessing` steps in one `inference-tap-config`.
pub const MAX_PREPROCESSING_STEPS: usize = 8;
/// Largest width or height of a `frame-size` / `crop-rect`.
pub const MAX_FRAME_DIMENSION: u32 = 8192;
/// Highest `max-framerate` filter value or inference-tap `fps`.
pub const MAX_FRAMERATE: f32 = 120.0;
/// Allowed audio sample rates in Hz.
pub const SAMPLE_RATE_RANGE: RangeInclusive<u32> = 8_000..=192_000;
/// Allowed audio channel counts.
pub const CHANNELS_RANGE: RangeInclusive<u8> = 1..=8;
/// Allowed `encode-params.bitrate-kbps`.
pub const BITRATE_KBPS_RANGE: RangeInclusive<u32> = 16..=100_000;
/// Allowed `encode-params.keyframe-interval`.
pub const KEYFRAME_INTERVAL_RANGE: RangeInclusive<u32> = 1..=1_000;

/// Why a pipeline bound was violated.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PipelineError {
    #[error("pipeline has {0} steps; at most {MAX_PIPELINE_STEPS} allowed")]
    TooManySteps(usize),
    #[error("pipeline has {0} sinks; at most {MAX_PIPELINE_SINKS} allowed")]
    TooManySinks(usize),
    #[error("inference tap has {0} preprocessing steps; at most {MAX_PREPROCESSING_STEPS} allowed")]
    TooManyPreprocessingSteps(usize),
    #[error("frame size {width}x{height} is outside 1..={MAX_FRAME_DIMENSION} per side")]
    FrameSize { width: u32, height: u32 },
    #[error("crop rectangle does not fit inside the {frame_width}x{frame_height} frame")]
    CropOutOfBounds { frame_width: u32, frame_height: u32 },
    #[error("frame rate {0} is not finite and in (0, {MAX_FRAMERATE}]")]
    Framerate(f32),
    #[error("{field} {value} is outside {min}..={max}")]
    OutOfRange {
        field: &'static str,
        value: u32,
        min: u32,
        max: u32,
    },
    #[error("normalize needs a finite mean and a finite, non-zero std")]
    Normalize,
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

/// Check the `preprocessing` length of one `inference-tap-config`.
pub fn validate_preprocessing_len(steps: usize) -> Result<(), PipelineError> {
    if steps > MAX_PREPROCESSING_STEPS {
        Err(PipelineError::TooManyPreprocessingSteps(steps))
    } else {
        Ok(())
    }
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

/// Check optional audio parameters (`audio-params`, `plugin-pipe-config`).
pub fn validate_audio(sample_rate: Option<u32>, channels: Option<u8>) -> Result<(), PipelineError> {
    if let Some(rate) = sample_rate {
        in_range("sample rate", rate, &SAMPLE_RATE_RANGE)?;
    }
    if let Some(ch) = channels {
        let range = u32::from(*CHANNELS_RANGE.start())..=u32::from(*CHANNELS_RANGE.end());
        in_range("channels", u32::from(ch), &range)?;
    }
    Ok(())
}

/// Check optional `encode-params` bounds.
pub fn validate_encode(
    bitrate_kbps: Option<u32>,
    keyframe_interval: Option<u32>,
) -> Result<(), PipelineError> {
    if let Some(kbps) = bitrate_kbps {
        in_range("bitrate", kbps, &BITRATE_KBPS_RANGE)?;
    }
    if let Some(interval) = keyframe_interval {
        in_range("keyframe interval", interval, &KEYFRAME_INTERVAL_RANGE)?;
    }
    Ok(())
}

/// Check a `preprocessing-step::normalize(mean, std)`.
pub fn validate_normalize(mean: f32, std: f32) -> Result<(), PipelineError> {
    if mean.is_finite() && std.is_finite() && std != 0.0 {
        Ok(())
    } else {
        Err(PipelineError::Normalize)
    }
}

fn in_range(
    field: &'static str,
    value: u32,
    range: &RangeInclusive<u32>,
) -> Result<(), PipelineError> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(PipelineError::OutOfRange {
            field,
            value,
            min: *range.start(),
            max: *range.end(),
        })
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
    fn preprocessing_len() {
        assert_eq!(validate_preprocessing_len(0), Ok(()));
        assert_eq!(validate_preprocessing_len(MAX_PREPROCESSING_STEPS), Ok(()));
        assert_eq!(
            validate_preprocessing_len(MAX_PREPROCESSING_STEPS + 1),
            Err(PipelineError::TooManyPreprocessingSteps(
                MAX_PREPROCESSING_STEPS + 1
            ))
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

    #[test]
    fn audio_and_encode() {
        assert_eq!(validate_audio(None, None), Ok(()));
        assert_eq!(validate_audio(Some(8_000), Some(1)), Ok(()));
        assert_eq!(validate_audio(Some(192_000), Some(8)), Ok(()));
        assert!(validate_audio(Some(7_999), None).is_err());
        assert!(validate_audio(Some(192_001), None).is_err());
        assert!(validate_audio(None, Some(0)).is_err());
        assert!(validate_audio(None, Some(9)).is_err());
        assert_eq!(validate_encode(None, None), Ok(()));
        assert_eq!(validate_encode(Some(16), Some(1)), Ok(()));
        assert_eq!(validate_encode(Some(100_000), Some(1_000)), Ok(()));
        assert_eq!(
            validate_encode(Some(15), None),
            Err(PipelineError::OutOfRange {
                field: "bitrate",
                value: 15,
                min: 16,
                max: 100_000
            })
        );
        assert!(validate_encode(None, Some(0)).is_err());
        assert!(validate_encode(None, Some(1_001)).is_err());
    }

    #[test]
    fn normalize() {
        assert_eq!(validate_normalize(0.5, 0.25), Ok(()));
        assert_eq!(validate_normalize(-1.0, -2.0), Ok(()));
        for (m, sd) in [
            (0.0, 0.0),
            (f32::NAN, 1.0),
            (0.0, f32::INFINITY),
            (0.0, -0.0),
        ] {
            assert_eq!(validate_normalize(m, sd), Err(PipelineError::Normalize));
        }
    }
}
