//! Symbol-table patcher for ntbind-generated drivers.  Walks the `.symtbl`
//! section, decrypts each header's payload, resolves it against a target
//! system's PDB(s) / module base addresses, and writes the new encrypted
//! payload back in place.
pub mod discover;
pub mod patch;
pub mod pe;
pub mod walk;
