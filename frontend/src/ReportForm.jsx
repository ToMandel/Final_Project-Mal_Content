import { useState } from "react";

const ReportForm = ({existingReport = {},updateCallback}) => {
  const [subject, setSubject] = useState(existingReport.subject ||"");
  const [content, setContent] = useState(existingReport.content ||"");

const updating = Object.entries(existingReport).length !== 0;

  const onSubmit = async (e) => {
    e.preventDefault();
    const data = { subject, content };
    const url = "http://127.0.0.1:5000"+(updating?`/update_report/${existingReport.id}`:"create_report");
    const options = {
        method:  updating ? "PATCH":"POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
    };
    const response = await fetch(url, options);
    if (response.status !== 201 && response.status !== 200) {
        const result = await response.json();
        alert(result.message);
    } else {    
        updateCallback();
        alert("Report created successfully!");
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <div>
        <label htmlFor="subject">Subject</label>
        <input
          type="text"
          id="subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
      </div>
      <div>
        <label htmlFor="content">Content</label>
        <input
          type="text"
          id="content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
        />
      </div>
      <div>
        <button type="submit">{updating? "Update":"Create"}</button>
      </div>
    </form>
  );
};

export default ReportForm;
