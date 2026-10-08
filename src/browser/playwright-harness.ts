import { Browser, BrowserContext, chromium, Page, Route } from 'playwright';
import { Decision } from '../core/types';
import { SessionPolicy } from '../types';
import { BrowserAction, BrowserGuardian, BrowserObservation } from './guardian';
import { CrossSurfaceStore } from './cross-surface-store';

export interface PlaywrightHarnessOptions {
  storagePath: string;
  sessionId: string;
  trustedOrigins?: string[];
  allowedOrigins?: string[];
  javaScriptEnabled?: boolean;
  sessionPolicy?: SessionPolicy;
  headless?: boolean;
  approvalHandler?: (decision: Decision, action: BrowserAction) => boolean | Promise<boolean>;
}

export class GuardedBrowserHarness {
  private browser?: Browser;
  private context?: BrowserContext;
  private page?: Page;
  private readonly guardian: BrowserGuardian;
  private readonly networkDestinations = new Set<string>();
  private lastNetworkHold?: Decision;

  constructor(private readonly options: PlaywrightHarnessOptions) {
    this.guardian = new BrowserGuardian(new CrossSurfaceStore(options.storagePath), {
      trustedOrigins: options.trustedOrigins,
      allowedOrigins: options.allowedOrigins,
      sessionPolicy: options.sessionPolicy
    });
  }

  async start(): Promise<void> {
    this.browser = await chromium.launch({ headless: this.options.headless ?? true });
    this.context = await this.browser.newContext({
      acceptDownloads: false, serviceWorkers: 'block', javaScriptEnabled: this.options.javaScriptEnabled ?? true
    });
    this.context.setDefaultTimeout(5_000);
    this.context.setDefaultNavigationTimeout(15_000);
    // Context routing includes frames and the initial request of a popup. Page
    // routing alone misses that initial popup request. WebSockets have a separate API.
    await this.context.route('**/*', route => this.guardNetworkRoute(route));
    await this.context.routeWebSocket('**/*', socket => socket.close());
    this.page = await this.context.newPage();
    this.context.on('page', popup => { if (popup !== this.page) void popup.close(); });
    this.page.on('download', download => { void download.cancel(); });
    this.context.on('request', request => {
      try { this.networkDestinations.add(new URL(request.url()).origin); } catch { /* Ignore non-URL schemes. */ }
    });
  }

  async navigate(url: string): Promise<Decision> {
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'navigate',
      destination: url,
      capability: 'BROWSER_NAVIGATE'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) {
      this.networkDestinations.clear();
      this.lastNetworkHold = undefined;
      try {
        const response = await this.requirePage().goto(url, { waitUntil: 'load' });
        if (!response?.ok()) throw new Error('Navigation did not return a successful HTTP response');
      } catch (error) {
        if (this.lastNetworkHold) return this.lastNetworkHold;
        throw error;
      }
    }
    return decision;
  }

  async observe(): Promise<{ observation: BrowserObservation; evidenceCount: number; decision: Decision }> {
    const page = this.requirePage();
    const main = await page.evaluate(() => {
      const clone = document.body?.cloneNode(true) as HTMLElement | undefined;
      clone?.querySelectorAll('script,style').forEach(node => node.remove());
      clone?.querySelectorAll('p,div,li,h1,h2,h3,h4,h5,h6,section,header,footer,main,form,br').forEach(node => {
        node.prepend(document.createTextNode('\n'));
        node.append(document.createTextNode('\n'));
      });
      const visible = document.body?.innerText || '';
      const ingested = clone?.textContent || '';
      const attributes = Array.from(document.querySelectorAll('[aria-label],[alt],[title],meta[name="description"]'))
        .slice(0, 501).map(node => [node.getAttribute('aria-label'), node.getAttribute('alt'), node.getAttribute('title'), node.getAttribute('content')].filter(Boolean).join(' '));
      return {
        title: document.title,
        visibleText: visible.slice(0, 100_000),
        agentText: `${ingested}\n${attributes.join('\n')}`.slice(0, 100_000),
        inspectionComplete: visible.length <= 100_000 && ingested.length + attributes.join('\n').length < 100_000 &&
          attributes.length <= 500 && document.querySelectorAll('a[href]').length <= 200 && document.forms.length <= 50,
        links: Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(link => ({
          text: (link.textContent || '').trim(), href: (link as HTMLAnchorElement).href
        })),
        forms: Array.from(document.forms).slice(0, 50).map(form => ({
          action: form.action, method: form.method,
          fields: Array.from(form.elements).map(element => (element as HTMLInputElement).name).filter(Boolean)
        }))
      };
    });
    const frames: Array<{ url: string; visibleText: string; agentText?: string }> = [];
    let framesComplete = page.frames().length <= 20;
    for (const frame of page.frames().filter(item => item !== page.mainFrame()).slice(0, 19)) {
      try {
        const text = await frame.evaluate(() => {
          const clone = document.body?.cloneNode(true) as HTMLElement | undefined;
          clone?.querySelectorAll('script,style').forEach(node => node.remove());
          clone?.querySelectorAll('p,div,li,h1,h2,h3,section,form,br').forEach(node => {
            node.prepend(document.createTextNode('\n')); node.append(document.createTextNode('\n'));
          });
          return { visible: document.body?.innerText || '', agent: clone?.textContent || '' };
        });
        if (text.visible.length > 10_000 || text.agent.length > 10_000) framesComplete = false;
        frames.push({ url: frame.url(), visibleText: text.visible.slice(0, 10_000), agentText: text.agent.slice(0, 10_000) });
      } catch {
        framesComplete = false;
        frames.push({ url: frame.url(), visibleText: '[frame unavailable]' });
      }
    }
    const observation: BrowserObservation = {
      sessionId: this.options.sessionId,
      url: page.url(),
      origin: new URL(page.url()).origin,
      title: main.title,
      visibleText: main.visibleText,
      agentText: main.agentText,
      frames,
      links: main.links,
      forms: main.forms,
      networkDestinations: Array.from(this.networkDestinations),
      inspectionComplete: main.inspectionComplete && framesComplete
    };
    const result = this.guardian.observe(observation);
    return { observation, evidenceCount: result.evidence.length, decision: result.decision };
  }

  async fill(selector: string, value: string, labels: Array<'credential' | 'sensitive' | 'personal'> = []): Promise<Decision | undefined> {
    const page = this.requirePage();
    const inspection = await this.observe();
    if (inspection.decision.outcome !== 'ALLOW') return inspection.decision;
    const element = page.locator(selector);
    const type = await element.getAttribute('type');
    const fieldIdentity = `${await element.getAttribute('name')} ${await element.getAttribute('id')} ${await element.getAttribute('autocomplete')}`;
    const credential = type === 'password' || labels.includes('credential') || /password|secret|token|api[_-]?key|credential/i.test(fieldIdentity);
    if (credential) {
      const action: BrowserAction = {
        sessionId: this.options.sessionId,
        type: 'credential_entry',
        source: page.url(),
        destination: new URL(page.url()).origin,
        payload: { selector, valueLength: value.length },
        dataLabels: ['credential', 'sensitive'],
        capability: 'BROWSER_CREDENTIAL_ENTRY'
      };
      const decision = this.guardian.gate(action);
      if (!(await this.mayProceed(decision, action))) return decision;
    }
    const action: BrowserAction = {
      sessionId: this.options.sessionId, type: 'fill', source: page.url(), destination: page.url(),
      payload: { selector, valueLength: value.length }, dataLabels: labels, capability: 'BROWSER_FILL'
    };
    const decision = this.guardian.gate(action);
    if (!(await this.mayProceed(decision, action))) return decision;
    await element.fill(value);
    return undefined;
  }

  async submit(selector: string): Promise<Decision> {
    const page = this.requirePage();
    const inspection = await this.observe();
    if (inspection.decision.outcome !== 'ALLOW') return inspection.decision;
    const form = page.locator(selector);
    const details = await form.evaluate(node => {
      const target = node as HTMLFormElement;
      return {
        action: target.action,
        method: target.method,
        fields: Array.from(target.elements).map(element => (element as HTMLInputElement).name).filter(Boolean)
      };
    });
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'submit_form',
      source: page.url(),
      destination: details.action,
      payload: details,
      capability: 'BROWSER_SUBMIT_FORM'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) {
      this.lastNetworkHold = undefined;
      try {
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'load', timeout: 5_000 }).then(response => {
            if (!response?.ok()) throw new Error('Form navigation did not return a successful HTTP response');
          }),
          form.evaluate(node => (node as HTMLFormElement).submit())
        ]);
      } catch (error) {
        if (this.lastNetworkHold) return this.lastNetworkHold;
        throw error;
      }
    }
    return decision;
  }

  async download(selector: string): Promise<Decision> {
    return this.gateClick(selector, 'download', 'BROWSER_DOWNLOAD');
  }

  async followLink(selector: string): Promise<Decision> {
    const inspected = await this.observe();
    if (inspected.decision.outcome !== 'ALLOW') return inspected.decision;
    const href = await this.requirePage().locator(selector).evaluate(node => {
      if (!(node instanceof HTMLAnchorElement)) throw new Error('Selector must identify a link');
      return node.href;
    });
    return this.navigate(href);
  }

  async purchase(selector: string): Promise<Decision> {
    return this.gateClick(selector, 'purchase', 'BROWSER_PURCHASE');
  }

  async close(): Promise<void> {
    await this.context?.close();
    await this.browser?.close();
    this.page = undefined;
    this.context = undefined;
    this.browser = undefined;
  }

  private async guardNetworkRoute(route: Route): Promise<void> {
    const request = route.request();
    const method = request.method().toUpperCase();
    const destinationAllowed = !this.options.allowedOrigins || this.options.allowedOrigins.includes(new URL(request.url()).origin);
    const guarded = !destinationAllowed || !['GET', 'HEAD', 'OPTIONS'].includes(method) ||
      ['xhr', 'fetch', 'websocket'].includes(request.resourceType());
    if (!guarded) {
      await this.forwardRoute(route);
      return;
    }
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'network_request',
      source: this.page?.url(),
      destination: request.url(),
      payload: { method, resourceType: request.resourceType() },
      capability: 'BROWSER_NETWORK_REQUEST'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) await this.forwardRoute(route);
    else {
      this.lastNetworkHold = decision;
      await route.abort('blockedbyclient');
    }
  }

  private async forwardRoute(route: Route): Promise<void> {
    try {
      // Chromium's redirected requests can bypass the initial routing callback.
      // Fetch without following redirects; refuse the whole chain in this v1.
      const response = await route.fetch({ maxRedirects: 0, timeout: 15_000 });
      if (response.status() >= 300 && response.status() < 400 && response.headers().location) {
        const destination = new URL(response.headers().location, route.request().url()).href;
        this.lastNetworkHold = this.guardian.gate({ sessionId: this.options.sessionId, type: 'network_request',
          source: route.request().url(), destination, capability: 'BROWSER_NETWORK_REQUEST',
          denialReason: 'Automatic redirects are disabled at the guarded browser boundary' });
        await route.abort('blockedbyclient');
      } else {
        await route.fulfill({ response });
      }
      await response.dispose();
    } catch {
      await route.abort('failed').catch(() => undefined);
    }
  }

  private async gateClick(
    selector: string,
    type: 'download' | 'purchase',
    capability: string
  ): Promise<Decision> {
    const page = this.requirePage();
    const inspected = await this.observe();
    if (inspected.decision.outcome !== 'ALLOW') return inspected.decision;
    const element = page.locator(selector);
    const href = await element.getAttribute('href');
    const destination = href ? new URL(href, page.url()).toString() : page.url();
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type,
      source: page.url(),
      destination,
      payload: { selector, text: await element.innerText().catch(() => '') },
      capability
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) await element.click();
    return decision;
  }

  private async mayProceed(decision: Decision, action: BrowserAction): Promise<boolean> {
    if (decision.outcome === 'ALLOW') return true;
    if (decision.outcome === 'ASK' && this.options.approvalHandler) {
      const approved = await this.options.approvalHandler(decision, action);
      decision.userResponse = approved ? 'approve_once' : 'deny';
      return approved;
    }
    return false;
  }

  private requirePage(): Page {
    if (!this.page) throw new Error('Browser harness has not been started');
    return this.page;
  }
}
