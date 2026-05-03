/**
 * Password Strength Meter v2 - Secure Student Portal
 * Refined scoring logic for better distinction between strength levels.
 */

const passwordInput = document.getElementById('passwordInput');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    let strength = 0;

    // 1. Minimum existence check
    if (val.length > 0) {
        strength = 10; 
    }

    // 2. Length Assessment (Length is critical for entropy)
    if (val.length >= 8) strength += 20;   // Basic length
    if (val.length >= 12) strength += 10;  // Bonus for extra length

    // 3. Complexity Assessment (Weighted Scoring)
    if (val.match(/[A-Z]/)) strength += 20;                    // Uppercase: +20
    if (val.match(/[0-9]/)) strength += 20;                    // Digits: +20
    if (val.match(/[!@#$%^&*(),.?":{}|<>]/)) strength += 30;   // Symbols: +30 (Higher weight)

    // Ensure it doesn't exceed 100
    if (strength > 100) strength = 100;

    // Update UI - Bar Width
    strengthBar.style.width = strength + '%';
    
    // 4. Threshold Logic - More strict transitions
    if (val.length === 0) {
        strengthBar.style.width = '0%';
        strengthBar.className = 'progress-bar bg-secondary';
        strengthText.innerText = 'Start typing a password...';
    } 
    // Weak: Only short or simple lowercase strings (0 - 35)
    else if (strength <= 35) {
        strengthBar.className = 'progress-bar bg-danger';
        strengthText.innerHTML = '<span class="text-danger">Weak ❌</span>';
    } 
    // Moderate: Length + 1 complexity factor (36 - 65)
    else if (strength <= 65) {
        strengthBar.className = 'progress-bar bg-warning';
        strengthText.innerHTML = '<span class="text-warning">Moderate ⚠️</span>';
    } 
    // Strong: Length + 2 complexity factors (66 - 85)
    else if (strength <= 85) {
        strengthBar.className = 'progress-bar bg-info';
        strengthText.innerHTML = '<span class="text-info">Strong 🛡️</span>';
    } 
    // Very Secure: Everything combined (86+)
    else {
        strengthBar.className = 'progress-bar bg-success';
        strengthText.innerHTML = '<span class="text-success">Very Secure! 💪</span>';
    }
});