// ui-anim.js — tiny helpers
document.addEventListener('DOMContentLoaded', ()=> {
  // floating label fixer
  document.querySelectorAll('.field input').forEach(inp=>{
    inp.placeholder = ' ';
    if(inp.value && inp.value.length>0) {
      inp.dispatchEvent(new Event('input'));
    }
  });

  // button click animation
  document.querySelectorAll('.primary').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      btn.animate(
        [{transform:'scale(0.95)'}, {transform:'scale(1)'}],
        {duration:150, fill:'forwards'}
      );
    });
  });
});
