# Example: User says “PC bị đơ rồi tự khởi động lại”

Agent should NOT answer: “Run SFC, reinstall drivers, update BIOS.”

Agent response logic:
1. Clarify whether it is a full-system freeze, display-only freeze, BSOD, or sudden power reset.
2. Ask 3-5 highest-value questions only:
   - At freeze time, does audio continue/loop?
   - Can mouse move / CapsLock LED toggle?
   - Can another device ping/SSH/RDP it?
   - Does it happen under GPU/CPU load, idle, or wake-from-sleep?
   - Did driver/kernel/BIOS/hardware change before first occurrence?
3. If Windows, collect event timeline and dumps. If Linux, collect previous-boot journal/kernel logs and pstore if present.
4. Build differential:
   - GPU/display stack
   - kernel/driver crash
   - storage timeout
   - RAM/CPU hardware error
   - power/thermal reset
5. Choose one discriminating next test.
6. Only after evidence converges, propose repair and verification.
