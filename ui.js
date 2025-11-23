// ui.js — small interactions
document.addEventListener('DOMContentLoaded', function(){
  // button click animation
  document.querySelectorAll('.btn-primary, .btn').forEach(btn=>{
    btn.addEventListener('click', function(e){
      try {
        btn.animate([{ transform: 'scale(0.96)' }, { transform: 'scale(1)' }], { duration:150 });
      } catch(e){}
    });
  });

  // small fade-in animation helper
  document.querySelectorAll('.animate-pop').forEach(el=>{
    el.style.opacity = 0;
    setTimeout(()=> el.style.opacity = 1, 50);
  });
});
