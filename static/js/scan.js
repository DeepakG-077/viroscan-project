// Get references to elements
const urlScanForm = document.getElementById("url-scan-form");
const scanResultElem = document.getElementById("scan-result");
const spinnerElem = document.getElementById("scan-spinner");
const scanHistoryTable = document.getElementById("scan-history-table");

// Hide spinner initially
if (spinnerElem) {
  spinnerElem.style.display = "none";
}

// Handle form submission with AJAX
if (urlScanForm) {
  urlScanForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const url = document.getElementById("url-to-scan").value;

    // Show spinner
    if (spinnerElem) {
      spinnerElem.style.display = "inline-block";
    }

    try {
      const response = await fetch("/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ url })
      });

      // Hide spinner
      if (spinnerElem) {
        spinnerElem.style.display = "none";
      }

      if (!response.ok) {
        scanResultElem.innerText = "Scan failed: Server error";
        return;
      }

      const result = await response.json();

      // Show scan result
      scanResultElem.innerText = `Scan Result: ${result.result}`;

      // Add to scan history table
      addToScanHistory(result);

    } catch (error) {
      if (spinnerElem) {
        spinnerElem.style.display = "none";
      }
      console.error("Scan failed:", error);
      scanResultElem.innerText = "Scan failed: Network error";
    }
  });
}

// Add scanned result to history table
function addToScanHistory(scanData) {
  if (!scanHistoryTable) return;

  // Create a new row
  const newRow = document.createElement("tr");
  newRow.innerHTML = `
    <td>${scanData.date}</td>
    <td>${scanData.type}</td>
    <td>${scanData.target}</td>
    <td>${scanData.status}</td>
    <td>${scanData.result}</td>
  `;

  // Add new row at the top
  scanHistoryTable.insertBefore(newRow, scanHistoryTable.firstChild);

  // Remove extra rows after 3
  while (scanHistoryTable.rows.length > 3) {
    scanHistoryTable.deleteRow(scanHistoryTable.rows.length - 1); // Remove from bottom
  }
}

// (Optional) Load previous history from Flask on page load
window.addEventListener("DOMContentLoaded", async () => {
  const res = await fetch("/scan-history");
  const history = await res.json();

  const latestThree = history.slice(-3).reverse(); // latest 3
  latestThree.forEach(addToScanHistory);
});
