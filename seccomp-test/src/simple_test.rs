/*!
 * Simple seccomp test without ptrace first
 */

use std::env;
use tracing::{info, error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <program> [args...]", args[0]);
        std::process::exit(1);
    }

    info!("Testing basic seccomp functionality");
    
    // Set no_new_privs first
    unsafe {
        let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if result != 0 {
            let err = std::io::Error::last_os_error();
            error!("Failed to set PR_SET_NO_NEW_PRIVS: {} (result={})", err, result);
            return Err(format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", err).into());
        }
    }
    info!("✓ Set PR_SET_NO_NEW_PRIVS=1");
    
    // Test libseccomp basic functionality
    use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};
    
    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    info!("✓ Created seccomp filter context");
    
    // Add a simple rule - block a syscall that will definitely be called
    ctx.add_rule(ScmpAction::KillThread, ScmpSyscall::from_name("write")?)?;
    info!("✓ Added rule to kill write() calls");
    
    // Try to load it
    ctx.load()?;
    info!("✓ Seccomp filter loaded successfully!");
    
    // Now write() should kill the process
    info!("About to call write() - this should kill the process...");
    unsafe {
        libc::write(1, b"This write should fail\n".as_ptr() as *const libc::c_void, 23);
    }
    error!("ERROR: write() succeeded - seccomp filter did not work!");
    
    Ok(())
}