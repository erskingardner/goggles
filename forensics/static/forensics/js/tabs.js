// Hash-driven tab bar: buttons carry role=tab + data-panel pointing at the
// panel id. Deep links (#messages) and back/forward both resolve via hash.
const tabs = Array.from(document.querySelectorAll('.tab[role="tab"][data-panel]'));

if (tabs.length) {
  const select = (tab, focus = false) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.dataset.panel);
      if (panel) panel.hidden = !on;
    }
    if (focus) tab.focus();
  };

  const fromHash = () => {
    const id = `panel-${location.hash.slice(1)}`;
    return tabs.find((t) => t.dataset.panel === id);
  };

  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      history.replaceState(null, "", `#${tab.dataset.panel.replace(/^panel-/, "")}`);
      select(tab);
    });
    tab.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      const step = e.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
      history.replaceState(null, "", `#${next.dataset.panel.replace(/^panel-/, "")}`);
      select(next, true);
    });
  }

  window.addEventListener("hashchange", () => select(fromHash() || tabs[0]));
  select(fromHash() || tabs[0]);
}
