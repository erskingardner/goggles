const searchInput = document.querySelector("[data-group-search]");
const rows = Array.from(document.querySelectorAll("[data-group-row]"));
const emptyRow = document.querySelector("[data-group-search-empty]");
const countTitle = document.querySelector("[data-group-count-title]");

function groupCountLabel(count) {
  return `${count} ${count === 1 ? "Group" : "Groups"}`;
}

function applyGroupFilter() {
  if (!searchInput || rows.length === 0) return;

  const query = searchInput.value.trim().toLowerCase();
  let visibleCount = 0;

  rows.forEach((row) => {
    const groupRef = (row.dataset.groupRef || "").toLowerCase();
    const isVisible = query === "" || groupRef.includes(query);
    row.hidden = !isVisible;
    if (isVisible) visibleCount += 1;
  });

  if (emptyRow) {
    emptyRow.hidden = query === "" || visibleCount > 0;
  }

  if (countTitle) {
    countTitle.textContent = query === "" ? "All groups" : groupCountLabel(visibleCount);
  }
}

if (searchInput) {
  searchInput.addEventListener("input", applyGroupFilter);
  searchInput.addEventListener("search", applyGroupFilter);
  searchInput.addEventListener("change", applyGroupFilter);

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === "k") {
      event.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  applyGroupFilter();
}
