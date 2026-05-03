/**
 * Password Strength Meter - Security Audit Project
 * 
 * This script provides real-time visual feedback on password complexity.
 * It evaluates based on length, casing, digits, and special characters.
 */

const passwordInput = document.getElementById('passwordInput');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    let strength = 0;

    // Baseline: If the input is not empty, start with a minimum strength 
    // to ensure the red bar is visible even for simple passwords like 'batuhan'.
    if (val.length > 0) {
        strength = 15; 
    }

    // Security Criteria Assessment
    if (val.length >= 8) strength += 20;                       // Criteria 1: Length check
    if (val.match(/[A-Z]/)) strength += 20;                    // Criteria 2: Uppercase check
    if (val.match(/[0-9]/)) strength += 20;                    // Criteria 3: Digit check
    if (val.match(/[!@#$%^&*(),.?":{}|<>]/)) strength += 25;   // Criteria 4: Symbol check

    // Update UI - Bar Width
    strengthBar.style.width = strength + '%';
    
    // Update UI - Dynamic Colors and Feedback Messages
    if (val.length === 0) {
        // Empty state
        strengthBar.style.width = '0%';
        strengthBar.className = 'progress-bar bg-secondary';
        strengthText.innerText = 'Start typing a password...';
    } else if (strength <= 35) {
        // Weak state (e.g., only lowercase or short strings)
        strengthBar.className = 'progress-bar bg-danger';
        strengthText.innerHTML = '<span class="text-danger">Weak ❌</span> (Add uppercase, numbers, or symbols)';
    } else if (strength <= 55) {
        // Moderate state
        strengthBar.className = 'progress-bar bg-warning';
        strengthText.innerHTML = '<span class="text-warning">Moderate ⚠️</span>';
    } else if (strength <= 75) {
        // Strong state
        strengthBar.className = 'progress-bar bg-info';
        strengthText.innerHTML = '<span class="text-info">Strong 🛡️</span>';
    } else {
        // Excellent state
        strengthBar.className = 'progress-bar bg-success';
        strengthText.innerHTML = '<span class="text-success">Very Secure! 💪</span>';
    }
});