searchForm = document.querySelector('.search-form');

document.querySelector('#search-btn').onclick = () => {
  searchForm.classList.toggle('active');
}

window.onscroll = () => {
  searchForm.classList.remove('active');

  if (window.scrollY > 80) {
    document.querySelector('.header .header-2').classList.add('active');
  } else {
    document.querySelector('.header .header-2').classList.remove('active');
  }
}

window.onload = () => {
  if (window.scrollY > 80) {
    document.querySelector('.header .header-2').classList.add('active');
  } else {
    document.querySelector('.header .header-2').classList.remove('active');
  }

  fadeOut();
}


function fadeOut() {
  setTimeout(loader, 4000);
}

var swiper = new Swiper(".books-slider", {
  loop: true,
  centeredSlides: true,
  autoplay: {
    delay: 2500,
    disableOnInteraction: false,
  },
  breakpoints: {
    0: {
      slidesPerView: 1,
    },
    768: {
      slidesPerView: 2,
    },
    1024: {
      slidesPerView: 3,
    },
  },
});

var swiper = new Swiper(".featured-slider", {
  spaceBetween: 10,
  loop: true,
  centeredSlides: true,
  autoplay: {
    delay: 2500,
    disableOnInteraction: false,
  },
  navigation: {
    nextEl: ".swiper-button-next",
    prevEl: ".swiper-button-prev",
  },
  breakpoints: {
    0: {
      slidesPerView: 1,
    },
    450: {
      slidesPerView: 2,
    },
    768: {
      slidesPerView: 3,
    },
    1024: {
      slidesPerView: 4,
    },
  },
});



var swiper = new Swiper(".reviews-slider", {
  spaceBetween: 10,
  grabCursor: true,
  loop: true,
  centeredSlides: true,
  autoplay: {
    delay: 2500,
    disableOnInteraction: false,
  },
  breakpoints: {
    0: {
      slidesPerView: 1,
    },
    768: {
      slidesPerView: 2,
    },
    1024: {
      slidesPerView: 3,
    },
  },
});



document.addEventListener("DOMContentLoaded", function () {
  const menuToggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  const closeSidebar = document.getElementById("close-sidebar");
  const overlay = document.getElementById("overlay");

  // Open sidebar
  menuToggle.addEventListener("click", function () {
      sidebar.style.left = "0";
      overlay.style.display = "block"; // Show overlay
  });

  // Close sidebar
  closeSidebar.addEventListener("click", function () {
      sidebar.style.left = "-250px";
      overlay.style.display = "none"; // Hide overlay
  });

  // Close sidebar when clicking outside
  overlay.addEventListener("click", function () {
      sidebar.style.left = "-250px";
      overlay.style.display = "none"; // Hide overlay
  });
});



document.addEventListener("DOMContentLoaded", function () {
  const sidebar = document.getElementById("sidebar");
  const closeBtn = document.getElementById("close-sidebar");
  const openSidebarBtn = document.getElementById("open-sidebar"); // Add an open button somewhere

  if (openSidebarBtn) {
      openSidebarBtn.addEventListener("click", function () {
          sidebar.classList.add("active");
      });
  }

  if (closeBtn) {
      closeBtn.addEventListener("click", function () {
          sidebar.classList.remove("active");
      });
  }
});



