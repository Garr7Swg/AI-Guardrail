const $ = (selector) => document.querySelector(selector);
const authScreen = $("#authScreen");
const appShell = $("#appShell");
const authForm = $("#authForm");
const authError = $("#authError");
const loginTab = $("#loginTab");
const registerTab = $("#registerTab");
const nameField = $("#nameField");
const nameInput = $("#nameInput");
const passwordInput = $("#passwordInput");
const authSubmit = $("#authSubmit");
const messages = $("#messages");
const conversation = $("#conversation");
const welcomeState = $("#welcomeState");
const promptInput = $("#promptInput");
const sendButton = $("#sendButton");
const fileList = $("#fileList");
const toast = $("#toast");
const bootScreen = $("#bootScreen");
const bootStartedAt = performance.now();

let authMode = "login";
let currentUser = null;
let csrfToken = "";
let toastTimer = null;

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes((options.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showSignedOut();
    throw new Error(data.detail || `Request failed (${response.status})`);
  }
  return data;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3300);
}

function setAuthMode(mode) {
  authMode = mode;
  const registering = mode === "register";
  nameField.hidden = !registering;
  nameInput.required = registering;
  passwordInput.autocomplete = registering ? "new-password" : "current-password";
  passwordInput.minLength = registering ? 12 : 1;
  authSubmit.innerHTML = registering ? 'Create account <span>↗</span>' : 'Sign in <span>↗</span>';
  loginTab.classList.toggle("active", !registering);
  registerTab.classList.toggle("active", registering);
  loginTab.setAttribute("aria-selected", String(!registering));
  registerTab.setAttribute("aria-selected", String(registering));
  authError.textContent = "";
}

function showSignedOut() {
  currentUser = null;
  csrfToken = "";
  appShell.hidden = true;
  authScreen.hidden = false;
  passwordInput.value = "";
}

function showSignedIn(user) {
  currentUser = user;
  csrfToken = user.csrf_token;
  authScreen.hidden = true;
  appShell.hidden = false;
  $("#profileName").textContent = user.display_name;
  $("#profileEmail").textContent = user.email.toUpperCase();
  const initials = user.display_name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "S";
  $("#avatarInitials").textContent = initials;
  const image = $("#avatarImage");
  if (user.has_avatar) {
    image.hidden = false;
    image.src = `/api/auth/avatar?v=${Date.now()}`;
    image.onerror = () => { image.hidden = true; };
  } else {
    image.removeAttribute("src");
    image.hidden = true;
  }
  loadFiles();
}

async function restoreSession() {
  try {
    const user = await request("/api/auth/me");
    if (user.authenticated) showSignedIn(user);
    else showSignedOut();
  } catch {
    showSignedOut();
  } finally {
    await hideBootScreen();
  }
}

async function hideBootScreen() {
  const minimumDuration = 1000;
  const remaining = minimumDuration - (performance.now() - bootStartedAt);
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  if (!bootScreen) return;
  bootScreen.classList.add("leaving");
  await new Promise((resolve) => setTimeout(resolve, 400));
  bootScreen.remove();
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.textContent = "";
  authSubmit.disabled = true;
  const payload = {
    email: $("#emailInput").value.trim(),
    password: passwordInput.value,
  };
  if (authMode === "register") payload.display_name = nameInput.value.trim();
  try {
    const result = await request(`/api/auth/${authMode}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    passwordInput.value = "";
    showSignedIn(result);
  } catch (error) {
    authError.textContent = error.message;
  } finally {
    authSubmit.disabled = false;
  }
});

loginTab.addEventListener("click", () => setAuthMode("login"));
registerTab.addEventListener("click", () => setAuthMode("register"));

$("#signOutButton").addEventListener("click", async () => {
  try { await request("/api/auth/logout", { method: "POST" }); } catch { /* Local sign-out still clears the view. */ }
  showSignedOut();
  showToast("Signed out securely.");
});

function makeMessage(role, text, disclaimer = "", pending = false) {
  const wrapper = document.createElement("article");
  wrapper.className = `message ${role}${pending ? " pending" : ""}`;
  const mark = document.createElement("span");
  mark.className = "message-mark";
  mark.textContent = role === "user" ? "YOU" : "S";
  const content = document.createElement("div");
  content.className = "message-content";
  const meta = document.createElement("div");
  meta.className = "message-meta";
  meta.textContent = role === "user" ? "YOUR PROMPT" : "ARBITRATED RESPONSE";
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text;
  content.append(meta, bubble);
  if (disclaimer) {
    const note = document.createElement("div");
    note.className = "bubble disclaimer";
    note.textContent = disclaimer;
    content.append(note);
  }
  wrapper.append(mark, content);
  messages.append(wrapper);
  conversation.scrollTop = conversation.scrollHeight;
  return { wrapper, bubble, content };
}

$("#chatForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const prompt = promptInput.value.trim();
  if (!prompt || sendButton.disabled) return;
  welcomeState.classList.add("hidden");
  makeMessage("user", prompt);
  promptInput.value = "";
  promptInput.style.height = "auto";
  const pending = makeMessage("assistant", "Screening the prompt and reviewing a draft", "", true);
  const typingDots = document.createElement("span");
  typingDots.className = "typing-dots";
  typingDots.textContent = "•••";
  pending.bubble.append(typingDots);
  sendButton.disabled = true;
  $("#sessionCode").textContent = crypto.randomUUID().slice(0, 8).toUpperCase();
  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ prompt }),
    });
    const result = await response.json();
    if (response.status === 401) {
      showSignedOut();
      throw new Error("Your session expired. Sign in again.");
    }
    pending.wrapper.classList.remove("pending");
    pending.bubble.textContent = result.answer || "I dont know";
    if (result.disclaimer) {
      const note = document.createElement("div");
      note.className = "bubble disclaimer";
      note.textContent = result.disclaimer;
      pending.content.append(note);
    }
    if (result.blocked) {
      const label = document.createElement("div");
      label.className = "message-meta";
      label.textContent = "STOPPED BY PROMPT GUARDRAIL";
      pending.content.prepend(label);
    }
    if (response.status >= 500) showToast("The service returned its safe fallback.");
  } catch (error) {
    pending.wrapper.classList.remove("pending");
    pending.bubble.textContent = "I dont know";
    const note = document.createElement("div");
    note.className = "bubble disclaimer";
    note.textContent = "This service uses free-tier facilities, so cold starts can take some time.";
    pending.content.append(note);
    if (error.message) showToast(error.message);
  } finally {
    sendButton.disabled = false;
    promptInput.focus();
    conversation.scrollTop = conversation.scrollHeight;
  }
});

promptInput.addEventListener("input", () => {
  promptInput.style.height = "auto";
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 170)}px`;
});
promptInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    $("#chatForm").requestSubmit();
  }
});

$("#newChatButton").addEventListener("click", () => {
  messages.replaceChildren();
  welcomeState.classList.remove("hidden");
  $("#sessionCode").textContent = "READY";
  promptInput.focus();
});

function prettySize(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

async function loadFiles() {
  try {
    const data = await request("/api/files");
    fileList.replaceChildren();
    $("#vaultCount").textContent = String(data.files.length);
    if (!data.files.length) {
      const empty = document.createElement("p");
      empty.className = "empty-files";
      empty.textContent = "Your vault is empty.";
      fileList.append(empty);
      return;
    }
    for (const file of data.files) {
      const row = document.createElement("div");
      row.className = "file-item";
      const icon = document.createElement("span");
      icon.className = "file-icon";
      icon.textContent = (file.name.split(".").pop() || "FILE").slice(0, 4).toUpperCase();
      const info = document.createElement("div");
      info.className = "file-info";
      const link = document.createElement("a");
      link.className = "file-name";
      link.href = `/api/files/${encodeURIComponent(file.id)}`;
      link.textContent = file.name;
      link.title = "Download original file";
      const size = document.createElement("small");
      size.className = "file-size";
      size.textContent = prettySize(file.size);
      info.append(link, size);
      const remove = document.createElement("button");
      remove.className = "delete-file";
      remove.type = "button";
      remove.textContent = "×";
      remove.title = "Delete document";
      remove.setAttribute("aria-label", `Delete ${file.name}`);
      remove.addEventListener("click", async () => {
        try {
          await request(`/api/files/${encodeURIComponent(file.id)}`, { method: "DELETE" });
          await loadFiles();
          showToast("Document deleted.");
        } catch (error) { showToast(error.message); }
      });
      row.append(icon, info, remove);
      fileList.append(row);
    }
  } catch (error) { showToast(error.message); }
}

$("#uploadButton").addEventListener("click", () => $("#documentInput").click());
$("#documentInput").addEventListener("change", async (event) => {
  const files = [...event.target.files];
  for (const file of files) {
    const data = new FormData();
    data.append("file", file);
    try {
      await request("/api/files", { method: "POST", body: data });
      showToast(`Uploaded ${file.name}`);
    } catch (error) { showToast(`${file.name}: ${error.message}`); }
  }
  event.target.value = "";
  await loadFiles();
});

$("#avatarButton").addEventListener("click", () => $("#avatarInput").click());
$("#avatarInput").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const data = new FormData();
  data.append("file", file);
  try {
    await request("/api/auth/avatar", { method: "POST", body: data });
    showSignedIn({ ...currentUser, has_avatar: true });
    showToast("Profile picture updated.");
  } catch (error) { showToast(error.message); }
  event.target.value = "";
});

restoreSession();
