import { Context } from 'hono';
import { DNSValidator } from '../services/dns-validator';

export class DNSController {
  private validator: DNSValidator;

  constructor() {
    this.validator = new DNSValidator();
  }

  // Get service information
  getInfo(c: Context) {
    return c.json({
      message: 'DNS Validator Service',
      usage: 'GET /validate?domain=example.com'
    });
  }

  // Validate domain
  async validateDomain(c: Context) {
    const domain = c.req.query('domain');

    if (!domain) {
      return c.json(
        { error: 'Domain parameter is required' },
        { status: 400 }
      );
    }

    const result = await this.validator.validateDNS(domain);
    const isDev = this.isDevelopmentEnvironment(c);

    const responseBody = isDev ? result : {
      exists: result.exists,
      error: result.error
    };

    return c.json(
      responseBody,
      { status: result.error ? 400 : 200 }
    );
  }

  // Handle errors
  handleError(err: Error, c: Context) {
    console.error(`${err}`);
    const isDev = this.isDevelopmentEnvironment(c);
    
    return c.json(
      { 
        error: 'Internal Server Error',
        details: isDev ? err.message : undefined
      },
      { status: 500 }
    );
  }

  // Handle 404
  handleNotFound(c: Context) {
    return c.json(
      { error: 'Not Found' },
      { status: 404 }
    );
  }

  // Check if running in development environment
  private isDevelopmentEnvironment(c: Context): boolean {
    const host = c.req.header('host') || '';
    return host.includes('localhost') || host.includes('127.0.0.1');
  }
} 