document.addEventListener('DOMContentLoaded', function() {
    const reportForm = document.querySelector('form');
    reportForm.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the form from submitting normally

        const reportData = document.getElementById('report').value;

        // Perform client-side validation for content length
        if (reportData.length > 500) { // 500 characters is the max allowed length
            showModal('Content is too long. Please shorten your content and try again.', 'text-danger');
            return;
        }

        // Check for invalid formats: only numbers, only special characters, or repeated words
        const isOnlyNumbers = /^\d+$/.test(reportData);
        const isOnlySpecialChars = /^[^\w\s]+$/.test(reportData); // Only non-word characters (special chars)
        const hasRepeatedWords = /\b(\w+)\b(?:\s+\1){2,}/gi.test(reportData); // Detect more than 2 repeated words
        const isOnlyUrl = /^(https?:\/\/[^\s]+)$/.test(reportData); // Detect if the input is only a URL

        if (isOnlyNumbers) {
            showModal('Content should not consist of only numbers. Please revise your content.', 'text-danger');
            return;
        }

        if (isOnlySpecialChars) {
            showModal('Content should not consist of only special characters. Please revise your content.', 'text-danger');
            return;
        }

        if (hasRepeatedWords) {
            showModal('Content contains repeated words more than two times in a row. Please revise your content.', 'text-danger');
            return;
        }

        if (isOnlyUrl) {
            showModal('Content should not consist of only a URL. Please add more context to your report.', 'text-danger');
            return;
        }

        // AJAX request to submit the form data
        fetch(reportForm.action, {
            method: 'POST',
            body: new FormData(reportForm)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error('Unknown error occurred.');
                });
            }
            return response.json();
        })
        .then(data => {
            const modalBody = document.querySelector('.modal-body');
            if (data.toxic) {
                modalBody.innerHTML = '<p class="text-danger">Malicious content detected in your report.</p>';
            } else {
                modalBody.innerHTML = '<p class="text-success">No malicious content found in your report.</p>';
            }
            $('#reportModal').modal('show');
        })
        .catch(error => {
            showModal(error.message, 'text-danger');
        });
    });

    function showModal(message, alertClass) {
        const modalBody = document.querySelector('.modal-body');
        modalBody.innerHTML = `<p class="${alertClass}">${message}</p>`;
        $('#reportModal').modal('show');
    }

    // Add event listener to redirect to reports list after closing the modal
    $('#reportModal').on('hidden.bs.modal', function () {
        const modalBodyText = document.querySelector('.modal-body p').textContent;
        if (modalBodyText.includes('Malicious content detected') || modalBodyText.includes('No malicious content found')) {
            window.location.href = "./reports";
        }
    });

    document.querySelector('.modal-footer .btn-secondary').addEventListener('click', function() {
        const modalBodyText = document.querySelector('.modal-body p').textContent;
        if (modalBodyText.includes('Malicious content detected') || modalBodyText.includes('No malicious content found')) {
            window.location.href = "./reports";
        }
    });
});
