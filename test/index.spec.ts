import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { waitOnExecutionContext as vitestPoolWorkersWaitOnExecutionContext } from '@cloudflare/vitest-pool-workers';
import app from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('Hello World worker', () => {
	it('responds with Hello World! (unit style)', async () => {
		const request = new IncomingRequest('http://example.com');
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		const data = await response.json();
		expect(data).toEqual({
			message: 'DNS Validator Service',
			usage: 'GET /validate?domain=example.com'
		});
	});

	it('responds with Hello World! (integration style)', async () => {
		const response = await SELF.fetch('https://example.com');
		const data = await response.json();
		expect(data).toEqual({
			message: 'DNS Validator Service',
			usage: 'GET /validate?domain=example.com'
		});
	});
});

describe('DNS Validator Service', () => {
	it('returns service information at root endpoint', async () => {
		const ctx = createExecutionContext();
		const request = new Request('http://localhost/', {
			headers: { 'host': 'localhost' }
		});
		const response = await app.fetch(request, {}, ctx);
		const data = await response.json();
		
		expect(data).toEqual({
			message: 'DNS Validator Service',
			usage: 'GET /validate?domain=example.com'
		});
		expect(response.status).toBe(200);
	});

	it('validates a domain successfully', async () => {
		const ctx = createExecutionContext();
		const request = new Request('http://localhost/validate?domain=example.com', {
			headers: { 'host': 'localhost' }
		});
		const response = await app.fetch(request, {}, ctx);
		const data = await response.json();
		
		expect(data).toHaveProperty('exists');
		expect(data).toHaveProperty('details');
		expect(data.details).toHaveProperty('status');
		expect(data.details).toHaveProperty('answer');
		expect(response.status).toBe(200);
	});

	it('returns 400 for missing domain parameter', async () => {
		const ctx = createExecutionContext();
		const request = new Request('http://localhost/validate', {
			headers: { 'host': 'localhost' }
		});
		const response = await app.fetch(request, {}, ctx);
		const data = await response.json();
		
		expect(data).toEqual({
			error: 'Domain parameter is required'
		});
		expect(response.status).toBe(400);
	});

	it('returns 404 for unknown routes', async () => {
		const ctx = createExecutionContext();
		const request = new Request('http://localhost/unknown', {
			headers: { 'host': 'localhost' }
		});
		const response = await app.fetch(request, {}, ctx);
		const data = await response.json();
		
		expect(data).toEqual({
			error: 'Not Found'
		});
		expect(response.status).toBe(404);
	});
});
