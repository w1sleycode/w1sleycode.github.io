const texts = [
    "(^_^)b",
    "(='X'=)",
    "\(o_o)/",
    "(^-^*)",
    "(˚Δ˚)b",
    "(='X'=)"
  ];

  const randomIndex = Math.floor(Math.random() * texts.length);
  const randomText = texts[randomIndex];

  const h1 = document.getElementById("random-text");
  h1.innerText = randomText;