const esbuild = require('esbuild');
const path = require('path');

const watch = process.argv.includes('--watch');
const minify = process.argv.includes('--minify');

async function main() {
  const extensionCtx = await esbuild.context({
    entryPoints: ['./src/extension.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/extension.js',
    external: ['vscode'],
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const proxyCtx = await esbuild.context({
    entryPoints: ['./src/proxy.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/proxy.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const coreCtx = await esbuild.context({
    entryPoints: ['./src/core/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/core.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    banner: { js: '#!/usr/bin/env node' },
  });

  const semanticWorkerCtx = await esbuild.context({
    entryPoints: ['./src/semantic-worker.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/semantic-worker.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const securityCtx = await esbuild.context({
    entryPoints: ['./src/security/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/security.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const reportingCtx = await esbuild.context({
    entryPoints: ['./src/reporting.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/reporting.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const cliCtx = await esbuild.context({
    entryPoints: ['./src/cli.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/cli.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    banner: { js: '#!/usr/bin/env node' },
  });

  const browserCtx = await esbuild.context({
    entryPoints: ['./src/browser/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/browser.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    external: ['playwright'],
  });

  const browserCliCtx = await esbuild.context({
    entryPoints: ['./src/browser-cli.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/browser-cli.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    external: ['playwright'],
    banner: { js: '#!/usr/bin/env node' },
  });

  const evaluationCtx = await esbuild.context({
    entryPoints: ['./src/evaluation/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/evaluation.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    external: ['playwright'],
  });

  const browserMcpCtx = await esbuild.context({
    entryPoints: ['./src/browser-mcp.ts'], bundle: true, platform: 'node',
    outfile: './dist/browser-mcp.js', format: 'cjs', sourcemap: true,
    minify, external: ['playwright'], banner: { js: '#!/usr/bin/env node' }
  });

  const evaluateCliCtx = await esbuild.context({
    entryPoints: ['./src/evaluate-cli.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/evaluate-cli.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
    external: ['playwright'],
    banner: { js: '#!/usr/bin/env node' },
  });

  if (watch) {
    console.log('Watching for changes...');
    await extensionCtx.watch();
    await proxyCtx.watch();
    await coreCtx.watch();
    await semanticWorkerCtx.watch();
    await securityCtx.watch();
    await reportingCtx.watch();
    await cliCtx.watch();
    await browserCtx.watch();
    await browserCliCtx.watch();
    await browserMcpCtx.watch();
    await evaluationCtx.watch();
    await evaluateCliCtx.watch();
  } else {
    await extensionCtx.rebuild();
    await proxyCtx.rebuild();
    await coreCtx.rebuild();
    await semanticWorkerCtx.rebuild();
    await securityCtx.rebuild();
    await reportingCtx.rebuild();
    await cliCtx.rebuild();
    await browserCtx.rebuild();
    await browserCliCtx.rebuild();
    await browserMcpCtx.rebuild();
    await evaluationCtx.rebuild();
    await evaluateCliCtx.rebuild();
    await extensionCtx.dispose();
    await proxyCtx.dispose();
    await coreCtx.dispose();
    await semanticWorkerCtx.dispose();
    await securityCtx.dispose();
    await reportingCtx.dispose();
    await cliCtx.dispose();
    await browserCtx.dispose();
    await browserCliCtx.dispose();
    await browserMcpCtx.dispose();
    await evaluationCtx.dispose();
    await evaluateCliCtx.dispose();
    console.log('Build completed successfully.');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
