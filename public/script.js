const reviewWrap = document.getElementById("reviewWrap");
const leftArrow = document.getElementById("leftArrow");
const rightArrow = document.getElementById("rightArrow");
const imgDiv = document.getElementById("imgDiv");
const personName = document.getElementById("personName");
const profession = document.getElementById("profession");
const description = document.getElementById("description");
const surpriseMeBtn = document.getElementById("surpriseMeBtn");
const chicken = document.querySelector(".chicken");

let isChickenVisible;

let people = [
	{
		photo:
			'url("https://cdn.pixabay.com/photo/2018/03/06/22/57/portrait-3204843_960_720.jpg")',
		name: "Susan Smith",
		profession: "WEB DEVELOPER",
		description:
		"I was impressed by the quality of service provided by Ride Partner. The ride was comfortable and the driver was friendly and professional."
	},

	{
		photo:
			"url('https://cdn.pixabay.com/photo/2019/02/11/20/20/woman-3990680_960_720.jpg')",
		name: "Anna Grey",
		profession: "UFC FIGHTER",
		description:
		"Ride Partner made my travel experience so much easier. The ride was affordable, and the driver was on time and courteous."
	},

	{
		photo:
			"url('https://cdn.pixabay.com/photo/2016/11/21/12/42/beard-1845166_960_720.jpg')",
		name: "Branson Cook",
		profession: "ACTOR",
		description:
		"I highly recommend Ride Partner. The ride was smooth, and the driver was knowledgeable about the area. I will definitely use their services again."
	}

	
];

imgDiv.style.backgroundImage = people[0].photo;
personName.innerText = people[0].name;
profession.innerText = people[0].profession;
description.innerText = people[0].description;
let currentPerson = 0;

//Select the side where you want to slide
function slide(whichSide, personNumber) {
	let reviewWrapWidth = reviewWrap.offsetWidth + "px";
	let descriptionHeight = description.offsetHeight + "px";
	//(+ or -)
	let side1symbol = whichSide === "left" ? "" : "-";
	let side2symbol = whichSide === "left" ? "-" : "";

	let tl = gsap.timeline();

	if (isChickenVisible) {
		tl.to(chicken, {
			duration: 0.4,
			opacity: 0
		});
	}

	tl.to(reviewWrap, {
		duration: 0.4,
		opacity: 0,
		translateX: `${side1symbol + reviewWrapWidth}`
	});

	tl.to(reviewWrap, {
		duration: 0,
		translateX: `${side2symbol + reviewWrapWidth}`
	});

	setTimeout(() => {
		imgDiv.style.backgroundImage = people[personNumber].photo;
	}, 400);
	setTimeout(() => {
		description.style.height = descriptionHeight;
	}, 400);
	setTimeout(() => {
		personName.innerText = people[personNumber].name;
	}, 400);
	setTimeout(() => {
		profession.innerText = people[personNumber].profession;
	}, 400);
	setTimeout(() => {
		description.innerText = people[personNumber].description;
	}, 400);

	tl.to(reviewWrap, {
		duration: 0.4,
		opacity: 1,
		translateX: 0
	});

	if (isChickenVisible) {
		tl.to(chicken, {
			duration: 0.4,
			opacity: 1
		});
	}
}

function setNextCardLeft() {
	if (currentPerson === 3) {
		currentPerson = 0;
		slide("left", currentPerson);
	} else {
		currentPerson++;
	}

	slide("left", currentPerson);
}

function setNextCardRight() {
	if (currentPerson === 0) {
		currentPerson = 3;
		slide("right", currentPerson);
	} else {
		currentPerson--;
	}

	slide("right", currentPerson);
}

leftArrow.addEventListener("click", setNextCardLeft);
rightArrow.addEventListener("click", setNextCardRight);

// surpriseMeBtn.addEventListener("click", () => {
// 	if (chicken.style.opacity === "0") {
// 		chicken.style.opacity = "1";
// 		imgDiv.classList.add("move-head");
// 		surpriseMeBtn.innerText = "Remove the chicken";
// 		surpriseMeBtn.classList.remove("surprise-me-btn");
// 		surpriseMeBtn.classList.add("hide-chicken-btn");
// 		isChickenVisible = true;
// 	} else if (chicken.style.opacity === "1") {
// 		chicken.style.opacity = "0";
// 		imgDiv.classList.remove("move-head");
// 		surpriseMeBtn.innerText = "Surprise me";
// 		surpriseMeBtn.classList.add("surprise-me-btn");
// 		surpriseMeBtn.classList.remove("hide-chicken-btn");
// 		isChickenVisible = false;
// 	}
// });
const inputs = document.querySelectorAll(".input");

function focusFunc() {
  let parent = this.parentNode;
  parent.classList.add("focus");
}

function blurFunc() {
  let parent = this.parentNode;
  if (this.value == "") {
    parent.classList.remove("focus");
  }
}

inputs.forEach((input) => {
  input.addEventListener("focus", focusFunc);
  input.addEventListener("blur", blurFunc);
});

window.addEventListener("resize", () => {
	description.style.height = "100%";
});