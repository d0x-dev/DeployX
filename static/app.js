// Simple shimmer on buttons when page becomes interactive
window.addEventListener('load', () => {
  const btns = document.querySelectorAll('.btn');
  btns.forEach((b, i) => setTimeout(() => b.classList.add('shine'), 150 * i));
});
