


//   let typeSplit = new SplitType('[animate]', {
//   script for gsap 
{/* <script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/TextPlugin.min.js"></script> */}
{/* <script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/ScrollTrigger.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/gsap.min.js"></script> -->

    <!-- <script>
        gsap.registerPlugin(ScrollTrigger);
        document.addEventListener("DOMContentLoaded", function(event) {
  animation_text_1("text-anim");
});

function animation_text_1 (element){
  var newText = "";
  var theText = document.querySelector(element);
  for (i = 0; i < theText.innerText.length; i++) {
    newText += "<div>";
    if (theText.innerText[i] == " "){newText += "&nbsp;"}
    else {newText += theText.innerText[i];}
    newText += "</div>";
  }
  theText.innerHTML = newText;
}

let tl = gsap.timeline({
  scrollTrigger: {
    trigger: ".container2",
    pin: true,
    scrub: true,
    end: "+=40%",
    pinSpaceing: false,
    markers: true
    
  }
});

let panels = gsap.utils.toArray(".panel");

panels.forEach((panel, i) => {
  
  if (!i) {
    tl.set({}, {}, 0.5)
  } else {
    tl.to(panel, {
      yPercent: -100,
      ease: "none"
    }, "+=1")
  }
})
    </script> -->
    <!-- <script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/gsap.min.js"></script>

<script src="/[YOUR_DIRECTORY]/GSDevTools.min.js"></script>
<script src="/[YOUR_DIRECTORY]/SplitText.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/TextPlugin.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/ScrollTrigger.min.js"></script>
   
    
    <script>
      
 document.addEventListener("DOMContentLoaded", (event) => {
  gsap.registerPlugin(SplitText)
  const rotatingHeaders = document.querySelectorAll(".rotatingHeader")

function initHeaders() {
  rotatingHeaders.forEach((header, index) => {
    let original = header.querySelectorAll("h3");
    let clone = original.cloneNode(true)
    header.appendChild(clone)
    gsap.set(clone, {yPercent:-100})
    header.originalSplit = SplitText.create(original, {type:"chars"})
    header.cloneSplit = SplitText.create(clone, {type:"chars"})
    ScrollTrigger.create({
      trigger:header,
      start:"top 50%",
      end:"bottom 30%",
      markers:true,
      //scrub:true,
      toggleActions:"play none none reverse",
      animation:createHeaderAnimation(header),
      invalidateOnRefresh:false
    })
  })	
}

function createHeaderAnimation(header) {
     console.log("createHeader")
    let duration = 0.4
    let stagger = {each:0.03, ease:"power1", 	from:"start"}
     gsap.set(header.cloneSplit.chars, {opacity:0})
    
    
    
    let tl = gsap.timeline()
    tl.set(header.cloneSplit.chars, {rotationX:-90, transformOrigin:() => {
      let height = header.offsetHeight
      return `50% 50% -${height/2}`
    }})
    
    tl.to(header.originalSplit.chars, {duration:duration, rotationX:90, transformOrigin:() => {
      let height = header.offsetHeight
      return `50% 50% -${height/2}`
    }, stagger:stagger})
    tl.to(header.originalSplit.chars, {duration:duration, opacity:0, stagger:stagger, ease:"power2.in"}, 0)
    
    tl.to(header.cloneSplit.chars, {duration:0.001, opacity:1, stagger:stagger}, 0.001)
    tl.to(header.cloneSplit.chars, {duration:duration, rotationX:0, stagger:stagger}, 0)
    return tl
    


}

initHeaders()

gsap.config({trialWarn:false})
 });
   
    
    
   </script>     */}
