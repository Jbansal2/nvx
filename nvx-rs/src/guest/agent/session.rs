use std::io;

use crate::protocol::{
    self, APP_ERROR, OUTER_ACK, OUTER_CREDIT, OUTER_DATA, OUTER_GUEST_ATTACH, OUTER_HEADER_LEN,
    OUTER_MAX_PAYLOAD, OUTER_RECEIVE_WINDOW, OUTER_RESET, OuterHeader,
};

use super::diagnostics::{read_exact, write_all};

pub(crate) struct Record {
    pub(crate) header: OuterHeader,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct Session {
    pub(crate) fd: libc::c_int,
    pub(crate) instance_id: [u8; 16],
    pub(crate) epoch: u64,
    pub(crate) guest_sequence: u64,
    pub(crate) host_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataFailureKind {
    Sequence,
    Identity,
    Application,
    Credit,
}

pub(crate) struct DataFailure {
    pub(crate) kind: DataFailureKind,
    pub(crate) status: i32,
    error: io::Error,
}

impl DataFailure {
    pub(crate) fn into_error(self) -> io::Error {
        self.error
    }
}

impl Session {
    pub(crate) fn new(fd: libc::c_int) -> Self {
        Self {
            fd,
            instance_id: [0; 16],
            epoch: 0,
            guest_sequence: 0,
            host_sequence: 0,
        }
    }

    pub(crate) fn send_attach(&mut self) -> io::Result<()> {
        self.write_outer(OUTER_GUEST_ATTACH, &[0; 16], 0, 0, &[])
    }

    pub(crate) fn acknowledge_reset(&mut self, record: &Record) -> io::Result<()> {
        if record.header.record_type != OUTER_RESET
            || !record.payload.is_empty()
            || record.header.epoch == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EPROTO));
        }
        self.instance_id = record.header.instance_id;
        self.epoch = record.header.epoch;
        self.guest_sequence = 0;
        self.host_sequence = record.header.sequence.wrapping_add(1);
        let payload = protocol::encode_ack_payload(OUTER_RECEIVE_WINDOW).map_err(protocol_error)?;
        self.write_outer(
            OUTER_ACK,
            &self.instance_id,
            self.epoch,
            self.guest_sequence,
            &payload,
        )?;
        self.guest_sequence = 1;
        Ok(())
    }

    pub(crate) fn send_record(&mut self, record_type: u8, payload: &[u8]) -> io::Result<()> {
        self.write_outer(
            record_type,
            &self.instance_id,
            self.epoch,
            self.guest_sequence,
            payload,
        )?;
        self.guest_sequence = self.guest_sequence.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn send_credit(&mut self, bytes: usize) -> io::Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let bytes =
            u32::try_from(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let payload = protocol::encode_credit_payload(bytes).map_err(protocol_error)?;
        self.send_record(OUTER_CREDIT, &payload)
    }

    pub(crate) fn send_app(
        &mut self,
        kind: u8,
        request_id: u64,
        status: i32,
        payload: &[u8],
    ) -> io::Result<()> {
        if protocol::APP_HEADER_LEN
            .checked_add(payload.len())
            .is_none_or(|length| length > OUTER_MAX_PAYLOAD)
        {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        let frame = protocol::encode_app(kind, request_id, status, payload);
        self.send_record(OUTER_DATA, &frame)
    }

    pub(crate) fn send_error(
        &mut self,
        request_id: u64,
        status: i32,
        category: &str,
    ) -> io::Result<()> {
        self.send_app(APP_ERROR, request_id, status, category.as_bytes())
    }

    pub(crate) fn read_record(&mut self) -> io::Result<Record> {
        let mut header = [0u8; OUTER_HEADER_LEN];
        read_exact(self.fd, &mut header)?;
        let header = protocol::decode_outer_header(&header).map_err(protocol_error)?;
        let mut payload = vec![0; header.length];
        read_exact(self.fd, &mut payload)?;
        Ok(Record { header, payload })
    }

    pub(crate) fn validate_data<'a>(
        &mut self,
        record: &'a Record,
    ) -> Result<protocol::AppFrame<'a>, DataFailure> {
        if record.header.record_type != OUTER_DATA || record.header.sequence != self.host_sequence {
            return Err(data_failure(
                DataFailureKind::Sequence,
                record.header.sequence as i32,
            ));
        }
        if record.header.epoch != self.epoch || record.header.instance_id != self.instance_id {
            return Err(data_failure(
                DataFailureKind::Identity,
                record.header.epoch as i32,
            ));
        }
        let frame = protocol::decode_app(&record.payload)
            .map_err(|_| data_failure(DataFailureKind::Application, record.payload.len() as i32))?;
        if frame.request_id == 0 || frame.status != 0 {
            return Err(data_failure(
                DataFailureKind::Application,
                record.payload.len() as i32,
            ));
        }
        self.host_sequence = self.host_sequence.wrapping_add(1);
        self.send_credit(record.payload.len())
            .map_err(|error| DataFailure {
                kind: DataFailureKind::Credit,
                status: record.payload.len() as i32,
                error,
            })?;
        Ok(frame)
    }

    fn write_outer(
        &self,
        record_type: u8,
        instance_id: &[u8; 16],
        epoch: u64,
        sequence: u64,
        payload: &[u8],
    ) -> io::Result<()> {
        let record = protocol::encode_outer(record_type, instance_id, epoch, sequence, payload)
            .map_err(protocol_error)?;
        write_all(self.fd, &record)
    }
}

fn protocol_error(_: protocol::ProtocolError) -> io::Error {
    io::Error::from_raw_os_error(libc::EPROTO)
}

fn data_failure(kind: DataFailureKind, status: i32) -> DataFailure {
    DataFailure {
        kind,
        status,
        error: io::Error::from_raw_os_error(libc::EPROTO),
    }
}
