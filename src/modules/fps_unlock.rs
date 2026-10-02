use std::ffi::c_void;
use std::io::Cursor;

use super::{MhyContext, MhyModule, ModuleType};
use crate::util;
use anyhow::Result;
use patternscan::scan;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

pub struct FpsUnlock;

// mov ecx, 0x3C(60); call rel32  ->  set_targetFrameRate(60)
const FPS_CAP_PATTERN: &str = "B9 3C 00 00 00 E8";
// 目标帧率 120 = 0x78
const TARGET_FPS_IMM: u8 = 0x78;

unsafe fn patch_byte(addr: *mut u8, value: u8) {
    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(
        addr as *const usize as *mut c_void,
        1,
        PAGE_EXECUTE_READWRITE,
        &mut old_prot,
    );
    *addr = value;
    let _ = VirtualProtect(
        addr as *const usize as *mut c_void,
        1,
        old_prot,
        &mut old_prot,
    );
}

impl MhyModule for MhyContext<FpsUnlock> {
    unsafe fn init(&mut self) -> Result<()> {
        crate::plog!("[FpsUnlock] scanning il2cpp for 60fps cap...");

        let Some((base, size)) = util::il2cpp_section_range(self.assembly_name) else {
            crate::plog!("[FpsUnlock] failed to locate il2cpp section");
            return Ok(());
        };

        let slice = std::slice::from_raw_parts(base, size);
        let mut cursor = Cursor::new(slice);
        let locs = scan(&mut cursor, FPS_CAP_PATTERN)?;

        let mut patched = 0;
        for loc in locs {
            let addr = base.add(loc);
            // addr 指向 B9 (mov ecx), addr+5 指向 E8 (call rel32)
            let rip = addr.add(5);
            let disp = *(rip.add(1) as *const i32);
            let dest = rip.add(5).offset(disp as isize);
            // 只 patch call 目标是 jmp thunk (E9) 的调用点
            if *dest == 0xE9 {
                patch_byte(addr.add(1), TARGET_FPS_IMM);
                crate::plog!("[FpsUnlock] patched 60fps -> {}fps at {:x}", TARGET_FPS_IMM, addr as usize);
                patched += 1;
            }
        }

        if patched == 0 {
            crate::plog!("[FpsUnlock] no matching 60fps cap call site found");
        } else {
            crate::plog!("[FpsUnlock] patched {} call site(s) to {} fps", patched, TARGET_FPS_IMM);
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> ModuleType {
        ModuleType::FpsUnlock
    }
}