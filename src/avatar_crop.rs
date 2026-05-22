use anyhow::Context;
use image::{
    GenericImageView, ImageEncoder,
    codecs::jpeg::JpegEncoder,
    imageops::{self, FilterType},
};

pub const AVATAR_OUTPUT_SIZE: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AvatarCrop {
    pub zoom: f32,
    pub pan_x: f32,
    pub pan_y: f32,
}

impl AvatarCrop {
    pub fn normalized(self) -> Self {
        Self {
            zoom: self.zoom.clamp(1.0, 3.0),
            pan_x: self.pan_x.clamp(-1.0, 1.0),
            pan_y: self.pan_y.clamp(-1.0, 1.0),
        }
    }
}

pub fn image_dimensions(bytes: &[u8]) -> anyhow::Result<(u32, u32)> {
    let image = image::load_from_memory(bytes).context("decode avatar image")?;
    Ok(image.dimensions())
}

pub fn crop_avatar_jpeg(bytes: &[u8], crop: AvatarCrop) -> anyhow::Result<Vec<u8>> {
    let crop = crop.normalized();
    let image = image::load_from_memory(bytes).context("decode avatar image")?;
    let (width, height) = image.dimensions();
    anyhow::ensure!(width > 0 && height > 0, "avatar image has empty dimensions");

    let shortest = width.min(height);
    let crop_size = ((shortest as f32) / crop.zoom)
        .round()
        .clamp(1.0, shortest as f32) as u32;

    let max_x = width.saturating_sub(crop_size);
    let max_y = height.saturating_sub(crop_size);
    let center_x = (max_x as f32 / 2.0) * (crop.pan_x + 1.0);
    let center_y = (max_y as f32 / 2.0) * (crop.pan_y + 1.0);
    let x = center_x.round().clamp(0.0, max_x as f32) as u32;
    let y = center_y.round().clamp(0.0, max_y as f32) as u32;

    let cropped = image.crop_imm(x, y, crop_size, crop_size).to_rgb8();
    let resized = imageops::resize(
        &cropped,
        AVATAR_OUTPUT_SIZE,
        AVATAR_OUTPUT_SIZE,
        FilterType::Lanczos3,
    );

    let mut out = Vec::new();
    JpegEncoder::new_with_quality(&mut out, 88)
        .write_image(
            resized.as_raw(),
            AVATAR_OUTPUT_SIZE,
            AVATAR_OUTPUT_SIZE,
            image::ExtendedColorType::Rgb8,
        )
        .context("encode cropped avatar")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    fn sample_png(width: u32, height: u32) -> Vec<u8> {
        let image = ImageBuffer::from_fn(width, height, |x, y| {
            Rgba([(x % 255) as u8, (y % 255) as u8, 128, 255])
        });
        let mut bytes = Vec::new();
        image
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();
        bytes
    }

    #[test]
    fn crop_avatar_outputs_fixed_size_jpeg() {
        let bytes = sample_png(1200, 800);
        let out = crop_avatar_jpeg(
            &bytes,
            AvatarCrop {
                zoom: 1.6,
                pan_x: 0.25,
                pan_y: -0.4,
            },
        )
        .unwrap();
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(
            decoded.dimensions(),
            (AVATAR_OUTPUT_SIZE, AVATAR_OUTPUT_SIZE)
        );
    }

    #[test]
    fn crop_normalizes_out_of_range_controls() {
        let crop = AvatarCrop {
            zoom: 9.0,
            pan_x: -5.0,
            pan_y: 4.0,
        }
        .normalized();
        assert_eq!(
            crop,
            AvatarCrop {
                zoom: 3.0,
                pan_x: -1.0,
                pan_y: 1.0,
            }
        );
    }
}
