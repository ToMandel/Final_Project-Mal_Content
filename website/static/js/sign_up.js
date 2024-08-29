document.addEventListener('DOMContentLoaded', function() {
    const password1 = document.getElementById('password1');
    const password2 = document.getElementById('password2');
    const passwordHelp = document.getElementById('passwordHelp');
    const passwordMatchHelp = document.getElementById('passwordMatchHelp');
    const submitButton = document.getElementById('submitButton');
    const strengthBar = document.getElementById('strengthBar');

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{7,}$/;

    function checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 7) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/\d/.test(password)) strength += 1;
        if (/[@$!%*?&]/.test(password)) strength += 1;
        return strength;
    }

    function updateStrengthBar(strength) {
        const percentage = (strength / 5) * 100;
        strengthBar.style.width = `${percentage}%`;

        if (strength <= 2) {
            strengthBar.classList.remove('bg-success', 'bg-warning');
            strengthBar.classList.add('bg-danger');
        } else if (strength <= 4) {
            strengthBar.classList.remove('bg-success', 'bg-danger');
            strengthBar.classList.add('bg-warning');
        } else {
            strengthBar.classList.remove('bg-warning', 'bg-danger');
            strengthBar.classList.add('bg-success');
        }
    }

    function validatePassword() {
        const strength = checkPasswordStrength(password1.value);
        updateStrengthBar(strength);

        if (strength < 3) {
            password1.classList.add('is-invalid');
            password1.classList.remove('is-valid');
            passwordHelp.textContent = 'Password is too weak.';
            passwordHelp.classList.add('text-danger');
            submitButton.disabled = true;
        } else {
            password1.classList.remove('is-invalid');
            password1.classList.add('is-valid');
            passwordHelp.textContent = '';
            passwordHelp.classList.remove('text-danger');
        }

        if (password1.value === password2.value && password2.value.length > 0) {
            password2.classList.remove('is-invalid');
            password2.classList.add('is-valid');
            passwordMatchHelp.textContent = '';
            if (password1.classList.contains('is-valid')) {
                submitButton.disabled = false;
            }
        } else {
            password2.classList.add('is-invalid');
            password2.classList.remove('is-valid');
            passwordMatchHelp.textContent = 'Passwords do not match.';
            passwordMatchHelp.classList.add('text-danger');
            submitButton.disabled = true;
        }
    }

    password1.addEventListener('input', validatePassword);
    password2.addEventListener('input', validatePassword);

    document.getElementById('signupForm').addEventListener('submit', function(event) {
        if (submitButton.disabled) {
            event.preventDefault();
        }
    });
});
