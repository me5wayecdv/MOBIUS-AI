/* MOBIUS site — small, dependency-free interactions. */

(() => {
  "use strict";

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------- nav */
  const burger = document.getElementById("burger");
  const links = document.getElementById("navLinks");
  if (burger && links) {
    burger.addEventListener("click", () => {
      const open = links.classList.toggle("is-open");
      burger.setAttribute("aria-expanded", String(open));
    });
    links.addEventListener("click", (e) => {
      if (e.target.closest("a")) {
        links.classList.remove("is-open");
        burger.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* -------------------------------------------------------------- tabs */
  document.querySelectorAll("[data-tabs]").forEach((root) => {
    const tabs = [...root.querySelectorAll("[role=tab]")];
    const panels = [...root.querySelectorAll("[data-panel]")];
    const status = root.querySelector(".js-status");
    const pct = root.querySelector(".js-pct");
    const labels = { findings: "analysing", device: "on device", api: "replaying", ci: "proposing fix" };
    const pcts = { findings: "68%", device: "100%", api: "92%", ci: "86%" };

    const select = (name) => {
      tabs.forEach((t) => {
        const on = t.dataset.tab === name;
        t.classList.toggle("is-active", on);
        t.setAttribute("aria-selected", String(on));
      });
      panels.forEach((p) => p.classList.toggle("is-active", p.dataset.panel === name));

      if (status) status.textContent = labels[name] || "analysing";
      if (pct) pct.textContent = pcts[name] || "68%";
      const scrub = root.querySelector(".console__scrub i");
      if (scrub) scrub.style.width = pcts[name] || "68%";
    };

    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => select(tab.dataset.tab));
      tab.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        e.preventDefault();
        const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        next.focus();
        select(next.dataset.tab);
      });
    });
  });

  /* ------------------------------------------------------- billing toggle */
  document.querySelectorAll("[data-billing]").forEach((box) => {
    const buttons = [...box.querySelectorAll("button")];
    buttons.forEach((btn) => {
      btn.addEventListener("click", () => {
        buttons.forEach((b) => b.classList.toggle("is-active", b === btn));
        const cycle = btn.dataset.cycle === "year" ? "year" : "month";
        document.querySelectorAll("[data-month]").forEach((el) => {
          el.textContent = el.dataset[cycle] || el.dataset.month;
        });
      });
    });
  });

  /* ---------------------------------------------------------- reveal */
  const revealables = document.querySelectorAll(".reveal");
  if (reduceMotion || !("IntersectionObserver" in window)) {
    revealables.forEach((el) => el.classList.add("is-in"));
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    revealables.forEach((el, i) => {
      el.style.transitionDelay = `${Math.min(i % 6, 5) * 60}ms`;
      io.observe(el);
    });
  }

  /* -------------------------------------------------- binary scramble */
  const scramble = (node) => {
    const original = node.dataset.original || node.textContent.trim() || "01";
    if (!node.dataset.original) node.dataset.original = original;
    const target = node.dataset.original.slice(0, Number(node.dataset.length) || original.length);

    if (reduceMotion) {
      node.textContent = target;
      return;
    }

    let frame = 0;
    const frames = 26;
    const timer = setInterval(() => {
      frame += 1;
      const settled = Math.floor((frame / frames) * target.length);
      let out = target.slice(0, settled);
      for (let i = settled; i < target.length; i += 1) {
        out += Math.random() > 0.5 ? "1" : "0";
      }
      node.textContent = out;
      if (frame >= frames) {
        clearInterval(timer);
        node.textContent = target;
      }
    }, 34);
  };

  document.querySelectorAll("[data-binary]").forEach((node) => {
    const original = node.textContent.trim();
    const want = Number(node.dataset.length) || original.length;
    // Build a deterministic-looking string of the requested length.
    const seed = "0110100101101110011100110110100101100101011001010111001101101001";
    node.dataset.original = (original + seed.repeat(4)).slice(0, want);
    node.textContent = node.dataset.original;
  });

  // Re-scramble the small marquee every few seconds; the big hero line once on entry.
  const marquees = [...document.querySelectorAll(".sheet .binary")];
  if (marquees.length && !reduceMotion) {
    let i = 0;
    setInterval(() => {
      scramble(marquees[i % marquees.length]);
      i += 1;
    }, 4200);
  }

  const heroBinary = document.querySelector(".hero__line--code .binary");
  if (heroBinary) {
    if (reduceMotion) {
      scramble(heroBinary);
    } else if ("IntersectionObserver" in window) {
      const once = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          scramble(heroBinary);
          once.disconnect();
        }
      });
      once.observe(heroBinary);
    } else {
      scramble(heroBinary);
    }
  }

  /* -------------------------------------------------- console autoplay */
  const consoleEl = document.getElementById("console");
  if (consoleEl && !reduceMotion) {
    const tabs = [...consoleEl.querySelectorAll("[role=tab]")];
    let index = 0;
    let paused = false;

    consoleEl.addEventListener("mouseenter", () => (paused = true));
    consoleEl.addEventListener("mouseleave", () => (paused = false));
    consoleEl.addEventListener("focusin", () => (paused = true));
    consoleEl.addEventListener("click", () => (paused = true));

    const tick = () => {
      if (!paused && !document.hidden) {
        index = (index + 1) % tabs.length;
        tabs[index].click();
      }
    };
    const timer = setInterval(tick, 5200);

    if ("IntersectionObserver" in window) {
      new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) return;
        paused = false;
        clearInterval(timer);
      }).observe(consoleEl);
    }
  }

  /* --------------------------------------------- nav shadow on scroll */
  const nav = document.getElementById("nav");
  if (nav) {
    const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }
})();
