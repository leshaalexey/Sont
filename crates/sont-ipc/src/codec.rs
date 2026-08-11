//! Кадрирование: длина-префикс + JSON.

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::protocol::Frame;

/// Потолок размера кадра.
///
/// Ограничение обязательное: без него сторона, севшая на сокет, заставляет
/// демон выделить произвольный объём памяти по заголовку длины. 4 МиБ с запасом
/// покрывают самый большой осмысленный ответ (хвост логов).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
    #[error("не удалось разобрать кадр: {0}")]
    Json(#[from] serde_json::Error),
}

/// Кодек кадров протокола.
pub struct FrameCodec {
    inner: LengthDelimitedCodec,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec {
    pub fn new() -> Self {
        Self {
            inner: LengthDelimitedCodec::builder()
                .max_frame_length(MAX_FRAME_BYTES)
                .length_field_type::<u32>()
                .big_endian()
                .new_codec(),
        }
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(bytes) = self.inner.decode(src)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = Bytes::from(serde_json::to_vec(&item)?);
        self.inner.encode(bytes, dst)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Hello, Request, Response};

    #[test]
    fn encode_decode_roundtrip() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        let frames = vec![
            Frame::Hello(Hello::new("0.1.0")),
            Frame::Request {
                id: 1,
                payload: Request::GetStatus,
            },
            Frame::Response {
                id: 1,
                payload: Response::Accepted,
            },
        ];

        for f in &frames {
            codec.encode(f.clone(), &mut buf).unwrap();
        }

        for expected in &frames {
            let got = codec.decode(&mut buf).unwrap().expect("кадр должен быть готов");
            assert_eq!(&got, expected);
        }
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn partial_frame_yields_nothing_until_complete() {
        let mut codec = FrameCodec::new();
        let mut full = BytesMut::new();
        codec
            .encode(Frame::Request { id: 1, payload: Request::GetStatus }, &mut full)
            .unwrap();

        // Скармливаем по байту: декодер не должен ничего вернуть, пока кадр
        // не придёт целиком, и не должен потерять уже принятое.
        let mut partial = BytesMut::new();
        for i in 0..full.len() - 1 {
            partial.extend_from_slice(&full[i..=i]);
            assert!(codec.decode(&mut partial).unwrap().is_none());
        }
        partial.extend_from_slice(&full[full.len() - 1..]);
        assert!(codec.decode(&mut partial).unwrap().is_some());
    }

    #[test]
    fn oversized_length_header_is_rejected() {
        // Заявленная длина больше потолка — декодер обязан отказать, а не
        // пытаться выделить память.
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&(u32::MAX).to_be_bytes());
        buf.extend_from_slice(b"{}");
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();
        let junk = b"not json at all";
        buf.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        buf.extend_from_slice(junk);
        assert!(matches!(codec.decode(&mut buf), Err(CodecError::Json(_))));
    }
}
