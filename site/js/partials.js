// Auctaryn — Shared Nav/Footer
// Single source of truth for site-wide links — change here, propagates everywhere.

const SITE_LINKS = {
  home: '/',
  pricing: '/pricing.html',
  docs: '/docs.html',
  about: '/about.html',
  dashboard: '/docs.html#quickstart',
  apiDocs: 'https://github.com/LloydCoder/Auctaryn',
  github: 'https://github.com/LloydCoder/Auctaryn',
  tinlance: 'https://tinlance.com',
  contact: 'mailto:hello@tinlance.com',
};

function renderNav(active) {
  const links = [
    { key: 'home', label: 'Product', href: SITE_LINKS.home + '#product' },
    { key: 'pricing', label: 'Pricing', href: SITE_LINKS.pricing },
    { key: 'docs', label: 'Docs', href: SITE_LINKS.docs },
    { key: 'about', label: 'About', href: SITE_LINKS.about },
    { key: 'dashboard', label: 'Demo setup', href: SITE_LINKS.dashboard },
  ];

  const linksHtml = links.map(l =>
    `<a href="${l.href}" class="${active === l.key ? 'active' : ''}" ${l.href.startsWith('http') ? 'target="_blank"' : ''}>${l.label}</a>`
  ).join('');

  const mobileLinksHtml = links.map(l =>
    `<a href="${l.href}" ${l.href.startsWith('http') ? 'target="_blank"' : ''}>${l.label}</a>`
  ).join('');

  document.write(`
    <nav>
      <div class="nav-inner">
        <a href="${SITE_LINKS.home}" class="logo">
          <div class="logo-icon">🛡</div>
          <span class="logo-text">Twin<span>Guard</span></span>
        </a>
        <div class="nav-links">${linksHtml}</div>
        <div class="nav-cta">
          <a href="${SITE_LINKS.pricing}" class="btn-ghost">See pricing</a>
          <a href="${SITE_LINKS.home}#cta" class="btn-primary">View source →</a>
        </div>
        <button class="hamburger" onclick="document.getElementById('mobileMenu').classList.toggle('open')">
          <span></span><span></span><span></span>
        </button>
      </div>
    </nav>
    <div class="mobile-menu" id="mobileMenu">
      ${mobileLinksHtml}
      <a href="${SITE_LINKS.home}#cta">View source</a>
    </div>
  `);
}

function renderFooter() {
  document.write(`
    <footer>
      <div class="footer-inner">
        <div class="footer-top">
          <div class="footer-brand">
            <a href="${SITE_LINKS.home}" class="logo">
              <div class="logo-icon" style="width:28px;height:28px;font-size:13px">🛡</div>
              <span class="logo-text" style="font-size:15px">Twin<span>Guard</span></span>
            </a>
            <p>Supported-path AI-agent governance controls built around a configured OpenShell runtime. Universal mediation and production readiness are not claimed.</p>
          </div>
          <div class="footer-col">
            <h4>Product</h4>
            <a href="${SITE_LINKS.home}#product">Overview</a>
            <a href="${SITE_LINKS.pricing}">Pricing</a>
            <a href="${SITE_LINKS.dashboard}" target="_blank">Demo setup</a>
            <a href="${SITE_LINKS.docs}">Documentation</a>
          </div>
          <div class="footer-col">
            <h4>Resources</h4>
            <a href="${SITE_LINKS.github}" target="_blank">GitHub</a>
            <a href="${SITE_LINKS.apiDocs}" target="_blank">API Reference</a>
            <a href="${SITE_LINKS.docs}#owasp">OWASP Coverage</a>
            <a href="${SITE_LINKS.docs}#demo">Demo Script</a>
          </div>
          <div class="footer-col">
            <h4>Company</h4>
            <a href="${SITE_LINKS.about}">About</a>
            <a href="${SITE_LINKS.tinlance}" target="_blank">Tinlance Limited</a>
            <a href="${SITE_LINKS.contact}">Contact</a>
          </div>
        </div>
        <div class="footer-bottom">
          <span class="footer-copy">© 2026 Tinlance Limited · RC: 7962164</span>
          <div class="footer-badges">
            <span class="footer-badge">Apache 2.0</span>
            <span class="footer-badge">Built on OpenShell</span>
            <span class="footer-badge">Release acceptance pending</span>
          </div>
        </div>
      </div>
    </footer>
  `);
}
