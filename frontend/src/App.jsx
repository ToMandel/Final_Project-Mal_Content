import { useState, useEffect } from "react";
import Reports from "./Reports";
import ReportForm from "./ReportForm";
import "./App.css";

function App() {
  const [reports, setReports] = useState([]);
  const [rules, setRules] = useState([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentReport, setCurrentReport] = useState({});

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    const response = await fetch("http://127.0.0.1:5000/");
    const data = await response.json();
    setReports(data.reports);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setCurrentReport({});
  };

  const openCreateModal = () => {
    if (!isModalOpen) setIsModalOpen(true);
  };

  const openEditModal = (report) => {
    if (isModalOpen) return;
    setCurrentReport(report);
    setIsModalOpen(true);
  };

  const onUpdate = () => {
    closeModal();
    fetchReports();
  };

  const onDelete = async (reportId) => {
    try{
    const options = {
      method : "DELETE"
    }
    const response = await fetch(`http://127.0.0.1:5000/delete_report/${reportId}`, options);
    if (response.status == 200) {
      updateCallback();
    }else{
      alert("Failed to delete report");
      console.error("Failed to delete report")
    }
  }catch(error){
    alert(error);
  }
}
      

  return (
    <>
      <Reports reports={reports} updateReport={openEditModal} updateCallback={onUpdate} />
      <button onClick={openCreateModal}>Create New Report</button>
      {isModalOpen && (
        <div className="modal">
          <div className="modal-content">
            <span className="close" onClick={closeModal}>
              &times;
            </span>
            <ReportForm existingReport={currentReport} updateCallback={onUpdate} />
          </div>
        </div>
      )}
    </>
  );
}

export default App;
