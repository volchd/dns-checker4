import { Context } from 'hono';
import { SPFValidator } from '../services/spf-validator';

export class SPFValidatorController {
  private validator: SPFValidator;

  constructor() {
    this.validator = new SPFValidator();
  }

  // Get service information
  getInfo(c: Context) {
    return c.json({
      message: 'SPF Validator Service',
      usage: 'GET /validate-spf?domain=example.com'
    });
  }

  // Validate SPF record
  async validateSPF(c: Context) {
    const domain = c.req.query('domain');
    console.log('Validating SPF for domain:', domain);

    if (!domain) {
      console.log('No domain parameter provided');
      return c.json(
        { error: 'Domain parameter is required' },
        { status: 400 }
      );
    }

    try {
      console.log('Starting SPF validation...');
      const result = await this.validator.validateSPF(domain);
      console.log('SPF validation result:', JSON.stringify(result, null, 2));
      
      const isDev = this.isDevelopmentEnvironment(c);

      const responseBody = isDev ? result : {
        isValid: result.isValid,
        score: result.score,
        issues: result.issues,
        recommendations: result.recommendations
      };

      return c.json(
        responseBody,
        { status: result.isValid ? 200 : 400 }
      );
    } catch (error) {
      console.error('Error during SPF validation:', error);
      return this.handleError(error as Error, c);
    }
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