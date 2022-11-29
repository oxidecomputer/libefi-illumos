use anyhow::{anyhow, Result};
use libefi_sys::{
    efi_alloc_and_read,
    efi_free,
    dk_gpt_t,
    dk_part_t,
};
use std::ffi::CStr;
use std::fs::File;
use std::ptr::{addr_of, addr_of_mut};
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use uuid::Uuid;

const GPT_ENT_TYPE_EFI: Uuid =
    Uuid::from_fields(
        0xc12a7328,
        0xf81f,
        0x11d2,
        &[0xba,0x4b,0x00,0xa0,0xc9,0x3e,0xc9,0x3b]
    );

const GPT_ENT_TYPE_ILLUMOS_BOOT: Uuid =
    Uuid::from_fields(
        0x6a82cb45,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_ILLUMOS_UFS: Uuid =
    Uuid::from_fields(
        0x6a85cf4d,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_ILLUMOS_ZFS: Uuid =
    Uuid::from_fields(
        0x6a898cc3,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_RESERVED: Uuid =
    Uuid::from_fields(
        0x6a945a3b,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

#[derive(Clone, Debug)]
pub enum GptEntryType {
    Efi,
    IllumosBoot,
    IllumosUFS,
    IllumosZFS,
    Reserved,
    Other(Uuid),
}

impl From<Uuid> for GptEntryType {
    fn from(uuid: Uuid) -> Self {
        match uuid {
            GPT_ENT_TYPE_EFI => GptEntryType::Efi,
            GPT_ENT_TYPE_ILLUMOS_BOOT => GptEntryType::IllumosBoot,
            GPT_ENT_TYPE_ILLUMOS_UFS => GptEntryType::IllumosUFS,
            GPT_ENT_TYPE_ILLUMOS_ZFS => GptEntryType::IllumosZFS,
            GPT_ENT_TYPE_RESERVED => GptEntryType::Reserved,
            _ => GptEntryType::Other(uuid),
        }
    }
}

pub struct Gpt {
    gpt: *mut dk_gpt_t,
}

impl Gpt {
    pub fn new(disk: File) -> Result<Self> {
        let fd = disk.as_fd();

        let mut gpt = std::ptr::null_mut();
        let retval = unsafe {
            efi_alloc_and_read(
                fd.as_raw_fd(),
                &mut gpt,
            )
        };
        match retval {
            n if n >= 0 => {
                println!("Slice Number: {n}");
                Ok(Self {
                    gpt,
                })
            }
            libefi_sys::VT_EIO => Err(anyhow!("I/O Error")),
            libefi_sys::VT_ERROR => Err(anyhow!("Unknown error occured")),
            libefi_sys::VT_EINVAL => Err(anyhow!("EFI label not found")),
            n => Err(anyhow!("Unhandled error: {n}")),
        }
    }

    fn raw_partitions(&self) -> &[dk_part_t] {
        unsafe {
            let count = (*self.gpt).efi_nparts as usize;
            let partitions_ptr = addr_of!((*self.gpt).efi_parts).cast();
            std::slice::from_raw_parts(partitions_ptr, count)
        }
    }

    fn raw_partitions_mut(&mut self) -> &mut [dk_part_t] {
        unsafe {
            let count = (*self.gpt).efi_nparts as usize;

            // NOTE: It's important to ensure that we don't have multiple mut
            // references to the underlying gpt object.
            let partitions_ptr = addr_of_mut!((*self.gpt).efi_parts).cast();

            std::slice::from_raw_parts_mut(partitions_ptr, count)
        }
    }

    pub fn block_size(&self) -> u32 {
        unsafe {
            (*self.gpt).efi_lbasize
        }
    }

    pub fn guid(&self) -> Uuid {
        let uuid = unsafe {
            let guid_ptr = addr_of!((*self.gpt).efi_disk_uguid) as *const u8;
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }

    pub fn partitions(&self) -> impl Iterator<Item = Partition<'_>> {
        self.raw_partitions()
            .iter()
            .enumerate()
            .map(|(index, part)| {
                Partition {
                    index,
                    part,
                }
            })
    }

    pub fn partitions_mut(&mut self) -> impl Iterator<Item = PartitionMut<'_>> {
        self.raw_partitions_mut()
            .iter_mut()
            .enumerate()
            .map(|(index, part)| {
                PartitionMut {
                    index,
                    part,
                }
            })
    }
}

impl Drop for Gpt {
    fn drop(&mut self) {
        unsafe {
            efi_free(self.gpt)
        }
    }
}

pub struct Partition<'a> {
    index: usize,
    part: &'a dk_part_t,
}

impl<'a> Partition<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.part.p_start
    }

    pub fn size(&self) -> u64 {
        self.part.p_size
    }

    pub fn partition_type_guid(&self) -> GptEntryType {
        let guid_ptr: *const u8 = addr_of!(self.part.p_guid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap().into()
    }

    pub fn tag(&self) -> u16 {
        self.part.p_tag
    }

    pub fn flag(&self) -> u16 {
        self.part.p_flag
    }

    pub fn name(&self) -> &CStr {
        if !self.part.p_name.as_slice().contains(&0) {
            return <&CStr>::default();
        }
        let name_ptr = addr_of!(self.part.p_name) as *const i8;
        unsafe {
            CStr::from_ptr(name_ptr)
        }
    }

    pub fn user_guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.part.p_uguid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }
}

pub struct PartitionMut<'a> {
    index: usize,
    part: &'a mut dk_part_t,
}

impl<'a> PartitionMut<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.part.p_start
    }

    pub fn set_start(&mut self, start: u64) {
        self.part.p_start = start;
    }

    pub fn size(&self) -> u64 {
        self.part.p_size
    }

    pub fn set_size(&mut self, size: u64) {
        self.part.p_size = size;
    }

    pub fn partition_type_guid(&self) -> GptEntryType {
        let guid_ptr: *const u8 = addr_of!(self.part.p_guid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap().into()
    }

    // TODO: Set part type

    pub fn tag(&self) -> u16 {
        self.part.p_tag
    }

    pub fn set_tag(&mut self, tag: u16) {
        self.part.p_tag = tag;
    }

    pub fn flag(&self) -> u16 {
        self.part.p_flag
    }

    pub fn set_flag(&mut self, flag: u16) {
        self.part.p_flag = flag;
    }

    pub fn name(&self) -> &CStr {
        if !self.part.p_name.as_slice().contains(&0) {
            return <&CStr>::default();
        }
        let name_ptr = addr_of!(self.part.p_name) as *const i8;
        unsafe {
            CStr::from_ptr(name_ptr)
        }
    }

    // TODO: Set name

    pub fn user_guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.part.p_uguid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }

    // TODO: Set user GUID
}
