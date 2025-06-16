import { Context } from 'hono';
import { SPFService } from '../services/spf.service';

export class SPFController {
  private spfService: SPFService;

  constructor() {
    this.spfService = new SPFService();
  }

  async getSPFRecord(c: Context) {
    const domain = c.req.query('domain');

    if (!domain) {
      return c.json({ error: 'Domain parameter is required' }, 400);
    }

    try {
      const spfRecord = await this.spfService.getSPFRecord(domain);
      
      if (!spfRecord) {
        return c.json({ error: 'No SPF record found for the domain' }, 404);
      }

      return c.json(spfRecord);
    } catch (error) {
      console.error('Error fetching SPF record:', error);
      return c.json({ error: 'Failed to fetch SPF record' }, 500);
    }
  }
} 