#![allow(unused_attributes)]
#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
program!(0xFFFFFFFE, "GPL");
#[xdp]
fn clean_dns(ctx: XdpContext) -> XdpResult {
    let ip = ctx.ip()?;
    if unsafe { (*ip).protocol as u32 } != IPPROTO_UDP
    {
        return Ok(XdpAction::Pass);
    }
    let transport = ctx.transport()?;
    // only match 53
    if transport.source() != 53 {
        return Ok(XdpAction::Pass);
    }

    // get first 10 byte udp data(7,8 is Answer RRs, 8,9 is Authority RRs)
    let udp_data = ctx.data()?;
    let data = udp_data.slice(12)?;

    // pass if the dns packet has multiple answers
    if data[6] != 0 || data[7] != 1 {
        // Answer RR != 1
        return Ok(XdpAction::Pass);
    }
    // pass if the dns packet has authority answer
    if data[8] != 0 || data[9] != 0 {
        // Authority RR != 0
        return Ok(XdpAction::Pass);
    }

    // drop if id is 0
    if unsafe { (*ip).id } == 0 &&
        unsafe { (*ip).frag_off } == 0 &&
        data[4] == 0x00 &&
        data[5] == 0x01 &&
        data[6] == 0x00 &&
        data[7] == 0x01 &&
        data[8] == 0x00 &&
        data[9] == 0x00 &&
        data[2] == 0x84 &&
        data[3] == 0x00
    {
        return Ok(XdpAction::Drop);
    }
    // drop if flag is 0x40(Don't fragment)
    if unsafe { (*ip).id } != 0 &&
        unsafe { (*ip).frag_off } == 0x0040 &&
        data[4] == 0x00 &&
        data[5] == 0x01 &&
        data[6] == 0x00 &&
        data[7] == 0x01 &&
        data[8] == 0x00 &&
        data[9] == 0x00 &&
        data[2] == 0x81 &&
        data[3] == 0x80
    {
        return Ok(XdpAction::Drop);
    }
    // drop ex.
    if data[4] == 0x00 &&
        data[5] == 0x01 &&
        data[6] == 0x00 &&
        data[7] == 0x01 &&
        data[8] == 0x00 &&
        data[9] == 0x00 &&
        data[10] == 0x00 &&
        data[11] == 0x00 &&
        data[2] == 0x85 &&
        (data[3] == 0x80 || data[3] == 0x90 || data[3] == 0xa0 || data[3] == 0xb0)
    {
        return Ok(XdpAction::Drop);
    }

    Ok(XdpAction::Pass)
}
