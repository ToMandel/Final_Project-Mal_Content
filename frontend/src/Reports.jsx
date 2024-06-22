import React from "react";

const Reports = ({ reports,updateReport,updateCallback }) => {
  return (
    <div>
      <h2>Reports</h2>
      <table>
        <thead></thead>
        <tr>
          <th>Report ID</th>
          <th>Content</th>
          <th>Created At</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
        <tbody>
          {reports.map((report) => (
            <tr key={report.id}>
              <td>{report.id}</td>
              <td>{report.content}</td>
              <td>{report.created_at}</td>
              <td>{report.status}</td>
              <td>
                <button onClick={() => createReport(report)}>Create</button>
                <button onClick={() => onDelete(report.id)}>Delete</button>
                <button onClick={() => updateReport(report)}>Update</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Reports;
