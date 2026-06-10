// Full-row click-through for table rows carrying data-href. The first cell
// keeps a real anchor for middle-click / keyboard; this handles the rest.
document.addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-href]");
  if (!row) return;
  if (e.target.closest("a, button")) return;
  if (String(getSelection())) return;
  location.href = row.dataset.href;
});
