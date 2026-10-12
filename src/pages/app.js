// Copy buttons on commands, copying by click on commits and fingerprints,
// and crates that tilt toward the pointer. The pages work without it.

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

document.querySelectorAll("pre.cmd").forEach((pre) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    const lines = [...pre.querySelectorAll(".ln")].map((line) => line.textContent);
    button.textContent = (await copy(lines.join("\n"))) ? "Copied" : "Select it";
    setTimeout(() => (button.textContent = "Copy"), 1600);
  });
  pre.appendChild(button);
});

document.querySelectorAll(".copyable").forEach((code) => {
  code.title = code.title || "Click to copy";
  code.addEventListener("click", async () => {
    if (await copy(code.textContent)) {
      code.classList.add("copied");
      setTimeout(() => code.classList.remove("copied"), 1200);
    }
  });
});

if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
  document.querySelectorAll(".tilt").forEach((crate) => {
    crate.addEventListener("pointermove", (event) => {
      const box = crate.getBoundingClientRect();
      const x = (event.clientX - box.left) / box.width - 0.5;
      const y = (event.clientY - box.top) / box.height - 0.5;
      crate.style.setProperty("--ry", `${x * 12}deg`);
      crate.style.setProperty("--rx", `${-y * 12}deg`);
    });
    crate.addEventListener("pointerleave", () => {
      crate.style.setProperty("--rx", "0deg");
      crate.style.setProperty("--ry", "0deg");
    });
  });
}
