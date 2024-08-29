function createReport(reportId) {
  fetch("/create-report", {
    method: "POST",
    body: JSON.stringify({ reportId: reportId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/reports";
  });
}

function deleteReport(reportId) {
  fetch("/delete-report", {
    method: "POST",
    body: JSON.stringify({ reportId: reportId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/reports";
  });
}

function updateReport(reportId) {
  fetch("/update-report", {
    method: "PUT",
    body: JSON.stringify({ reportId: reportId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/reports";
  });
}

function createRule(ruleId) {
  fetch("/create-rule", {
    method: "POST",
    body: JSON.stringify({ ruleId: ruleId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/rules";
  });
}

function deleteRule(ruleId) {
  fetch("/delete-rule", {
    method: "POST",
    body: JSON.stringify({ ruleId: ruleId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/rules";
  });
}

function updateRule(ruleId) {
  fetch("/update-rule", {
    method: "PUT",
    body: JSON.stringify({ ruleId: ruleId }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((_res) => {
    window.location.href = "/rules";
  });
}
