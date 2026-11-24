/**
 * EduPredict - Enterprise Interactive JavaScript & Animation Suite
 */

document.addEventListener('DOMContentLoaded', function () {
  // 1. Initialize Lucide Icons if available
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    window.lucide.createIcons();
  }

  // 2. Dark / Light Theme System with Persistence
  const savedTheme = localStorage.getItem('edupredict-theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);

  const themeToggleBtn = document.querySelector('.theme-toggle-btn');
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', function () {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('edupredict-theme', newTheme);
      updateThemeIcon(newTheme);
      showToast(`Switched to ${newTheme} mode`, 'info');
    });
  }

  function updateThemeIcon(theme) {
    const icon = document.querySelector('.theme-toggle-btn i');
    if (!icon) return;
    if (theme === 'dark') {
      icon.className = 'bi bi-sun-fill';
    } else {
      icon.className = 'bi bi-moon-stars-fill';
    }
  }

  // 3. Sidebar Collapse & Mobile Drawer
  const sidebarToggleBtn = document.querySelector('.sidebar-toggle-btn');
  const sidebar = document.querySelector('.app-sidebar');
  const backdrop = document.querySelector('.sidebar-backdrop');

  // Check saved desktop sidebar collapse state
  const isSidebarCollapsed = localStorage.getItem('edupredict-sidebar-collapsed') === 'true';
  if (isSidebarCollapsed && window.innerWidth > 992 && sidebar) {
    sidebar.classList.add('collapsed');
    document.body.classList.add('sidebar-collapsed');
  }

  if (sidebarToggleBtn && sidebar) {
    sidebarToggleBtn.addEventListener('click', function () {
      if (window.innerWidth <= 992) {
        // Mobile drawer toggle
        sidebar.classList.toggle('open');
        if (backdrop) backdrop.classList.toggle('active');
      } else {
        // Desktop collapse toggle
        sidebar.classList.toggle('collapsed');
        document.body.classList.toggle('sidebar-collapsed');
        const collapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('edupredict-sidebar-collapsed', collapsed);
      }
    });
  }

  if (backdrop && sidebar) {
    backdrop.addEventListener('click', function () {
      sidebar.classList.remove('open');
      backdrop.classList.remove('active');
    });
  }

  // 4. Smooth Counter Animations for Stat Values
  animateCounters();

  // 5. Password Visibility Toggle
  document.querySelectorAll('.toggle-password-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const input = this.parentElement.querySelector('input');
      const icon = this.querySelector('i');
      if (!input) return;

      if (input.type === 'password') {
        input.type = 'text';
        if (icon) {
          icon.classList.remove('bi-eye');
          icon.classList.add('bi-eye-slash');
        }
      } else {
        input.type = 'password';
        if (icon) {
          icon.classList.remove('bi-eye-slash');
          icon.classList.add('bi-eye');
        }
      }
    });
  });

  // 6. Modal Outside Click Handler
  window.addEventListener('click', function (e) {
    if (e.target.classList && (e.target.classList.contains('modal') || e.target.classList.contains('modal-backdrop'))) {
      e.target.style.display = 'none';
      e.target.classList.remove('active');
      e.target.classList.remove('show');
    }
  });

  // 7. Auto-dismiss Flash Alerts
  setTimeout(function () {
    document.querySelectorAll('.alert').forEach(function (alert) {
      alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-6px)';
      setTimeout(function () {
        if (alert.parentElement) alert.remove();
      }, 400);
    });
  }, 6000);
});

// Toast Notification Manager
window.showToast = function (message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let iconHtml = '<i class="bi bi-info-circle-fill" style="color: var(--secondary);"></i>';
  if (type === 'success') iconHtml = '<i class="bi bi-check-circle-fill" style="color: var(--success);"></i>';
  if (type === 'warning') iconHtml = '<i class="bi bi-exclamation-triangle-fill" style="color: var(--warning);"></i>';
  if (type === 'danger') iconHtml = '<i class="bi bi-x-circle-fill" style="color: var(--danger);"></i>';

  toast.innerHTML = `
    ${iconHtml}
    <div style="flex: 1;">${message}</div>
    <button style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px;" onclick="this.parentElement.remove()">
      <i class="bi bi-x"></i>
    </button>
  `;

  container.appendChild(toast);

  setTimeout(function () {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, duration);
};

// Counter Number Animation Helper
function animateCounters() {
  const counters = document.querySelectorAll('.stat-value');
  counters.forEach(function (counter) {
    const text = counter.innerText.trim();
    // Check if contains pure number or percentage
    const hasPercent = text.includes('%');
    const hasSlash = text.includes('/');
    let targetNum = parseFloat(text.replace(/[^0-9.]/g, ''));

    if (!isNaN(targetNum) && targetNum > 0 && !hasSlash) {
      let current = 0;
      const step = targetNum / 25;
      const timer = setInterval(function () {
        current += step;
        if (current >= targetNum) {
          current = targetNum;
          clearInterval(timer);
        }
        counter.innerText = (Number.isInteger(targetNum) ? Math.round(current) : current.toFixed(1)) + (hasPercent ? '%' : '');
      }, 20);
    }
  });
}

// Global Modal Helpers
window.openModal = function (modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'flex';
    modal.classList.add('active');
  }
};

window.closeModal = function (modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'none';
    modal.classList.remove('active');
  }
};

// Task & Recommendation Completion Toggle
window.toggleTask = function (buttonElement, taskId) {
  const isDone = buttonElement.classList.contains('done');
  if (isDone) {
    buttonElement.classList.remove('done');
    buttonElement.innerHTML = '<i class="bi bi-circle"></i> Mark Done';
    showToast('Task marked in-progress', 'info');
  } else {
    buttonElement.classList.add('done');
    buttonElement.innerHTML = '<i class="bi bi-check-circle-fill" style="color: var(--success);"></i> Completed';
    showToast('Task marked completed!', 'success');
  }
};

// Prediction Page Preset Helper
window.setPreset = function (att, int_m, asg, prev, study, part) {
  const attRange = document.getElementById('attRange');
  const attVal = document.getElementById('attVal');
  if (attRange) {
    attRange.value = att;
    if (attVal) attVal.textContent = att + '%';
  }

  const intRange = document.getElementById('intRange');
  const intVal = document.getElementById('intVal');
  if (intRange) {
    intRange.value = int_m;
    if (intVal) intVal.textContent = int_m;
  }

  const asgRange = document.getElementById('asgRange');
  const asgVal = document.getElementById('asgVal');
  if (asgRange) {
    asgRange.value = asg;
    if (asgVal) asgVal.textContent = asg + '%';
  }

  const prevRange = document.getElementById('prevRange');
  const prevVal = document.getElementById('prevVal');
  if (prevRange) {
    prevRange.value = prev;
    if (prevVal) prevVal.textContent = prev + '%';
  }

  const studyInput = document.querySelector('input[name="study_hours"]');
  if (studyInput) studyInput.value = study;

  const partInput = document.querySelector('input[name="participation"]');
  if (partInput) partInput.value = part;

  showToast('Preset academic parameters applied', 'info', 2000);
};
