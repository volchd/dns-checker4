import { Context } from 'hono';
import { DKIMValidator } from '../services/dkim-validator';

export class DKIMValidatorController {
  private validator: DKIMValidator;

  constructor() {
    this.validator = new DKIMValidator();
  }

  // Get service information
  getInfo(c: Context) {
    return c.json({
      message: 'DKIM Validator Service',
      usage: 'GET /validate-dkim?domain=example.com'
    });
  }

  // Validate DKIM record(s)
  async validateDKIM(c: Context) {
    const domain = c.req.query('domain');
    if (!domain) {
      return c.json(
        { error: 'Domain parameter is required' },
        { status: 400 }
      );
    }
    try {
      const result = await this.validator.validateDKIM(domain);
      const isDev = this.isDevelopmentEnvironment(c);
      const responseBody = isDev ? result : {
        isValid: result.isValid,
        score: result.score,
        records: result.records,
        issues: result.issues,
        recommendations: result.recommendations
      };
      return c.json(
        responseBody,
        { status: result.isValid ? 200 : 400 }
      );
    } catch (error) {
      return this.handleError(error as Error, c);
    }
  }

  // Handle errors
  handleError(err: Error, c: Context) {
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