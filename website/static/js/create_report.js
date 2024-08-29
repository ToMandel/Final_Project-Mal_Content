document.addEventListener('DOMContentLoaded', function() {
    const reportForm = document.querySelector('form');
    reportForm.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the form from submitting normally

        const reportData = document.getElementById('report').value;
        //Perform client-side validation for content length
        if (reportData.length > 500) { // 500 characters is the max allowed length
            showModal('Content is too long. Please shorten your content and try again.', 'text-danger');
            return;
        }
        //AJAX request to submit the form data
        fetch(reportForm.action, {
            method: 'POST',
            body: new FormData(reportForm)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Unknown error occurred.');
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
        window.location.href = "./reports";
    });

    document.querySelector('.modal-footer .btn-secondary').addEventListener('click', function() {
        window.location.href = "./reports"; 
    });
});