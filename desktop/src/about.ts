(function (): void {
  interface AboutGithubProfile {
    login: string;
    name: string | null;
    avatarDataUri: string;
    bio: string | null;
    company: string | null;
    location: string | null;
    htmlUrl: string;
    publicRepos: number;
    followers: number;
  }

  interface AboutPayload {
    profile: AboutGithubProfile | null;
    error: string | null;
    appVersion: string;
  }

  function $(id: string): HTMLElement {
    const el = document.getElementById(id);
    if (!el) throw new Error(`Missing element #${id}`);
    return el;
  }

  function escapeHtml(value: string): string {
    const div = document.createElement("div");
    div.textContent = value;
    return div.innerHTML;
  }

  function renderError(card: HTMLElement, message: string, appVersion: string): void {
    card.innerHTML = `
      <h2 class="about-name">KeyLock</h2>
      <p class="about-login">v${escapeHtml(appVersion)}</p>
      <p class="error">${escapeHtml(message)}</p>
    `;
  }

  function renderProfile(card: HTMLElement, profile: AboutGithubProfile, appVersion: string): void {
    const avatar = profile.avatarDataUri
      ? `<img class="about-avatar" src="${profile.avatarDataUri}" alt="${escapeHtml(profile.login)}" />`
      : "";
    const meta = [profile.company, profile.location].filter((v): v is string => Boolean(v));

    card.innerHTML = `
      ${avatar}
      <h2 class="about-name">${escapeHtml(profile.name ?? profile.login)}</h2>
      <p class="about-login">@${escapeHtml(profile.login)}</p>
      ${meta.map((line) => `<p class="hint">${escapeHtml(line)}</p>`).join("")}
      ${profile.bio ? `<p class="about-bio">${escapeHtml(profile.bio)}</p>` : ""}
      <div class="about-stats">
        <span>${profile.publicRepos} repos</span>
        <span>${profile.followers} followers</span>
      </div>
      <p class="about-app-info">
        KeyLock v${escapeHtml(appVersion)}<br />
        built by <a id="about-profile-link" href="#">${escapeHtml(profile.htmlUrl)}</a>
      </p>
    `;

    const link = document.getElementById("about-profile-link");
    link?.addEventListener("click", (event) => {
      event.preventDefault();
      void window.keylock.openExternal(profile.htmlUrl);
    });
  }

  const card = $("about-card");
  const params = new URLSearchParams(window.location.search);
  const raw = params.get("data");

  if (!raw) {
    renderError(card, "No profile data was passed to this window.", "0.0.0");
  } else {
    try {
      const payload = JSON.parse(decodeURIComponent(raw)) as AboutPayload;
      if (payload.profile) {
        renderProfile(card, payload.profile, payload.appVersion);
      } else {
        renderError(card, payload.error ?? "Could not load your GitHub profile.", payload.appVersion);
      }
    } catch {
      renderError(card, "Could not parse profile data.", "0.0.0");
    }
  }
})();
