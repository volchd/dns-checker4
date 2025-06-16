import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { prettyJSON } from 'hono/pretty-json';
import { DNSController } from './controllers/dns.controller';
import { SPFController } from './controllers/spf.controller';

// Create Hono app
const app = new Hono();

// Create controller instances
const dnsController = new DNSController();
const spfController = new SPFController();

// Middleware
app.use('*', cors());
app.use('*', prettyJSON());

// Routes
app.get('/', (c) => dnsController.getInfo(c));
app.get('/validate', (c) => dnsController.validateDomain(c));
app.get('/spf', (c) => spfController.getSPFRecord(c));

// Error handling
app.onError((err, c) => dnsController.handleError(err, c));

// 404 handler
app.notFound((c) => dnsController.handleNotFound(c));

export default app; 