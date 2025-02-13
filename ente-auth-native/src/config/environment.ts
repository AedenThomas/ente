interface Environment {
  apiUrl: string;
  accountsUrl: string;
  clientPackage: string;
}

const development: Environment = {
  apiUrl: 'https://api.ente.io',
  accountsUrl: 'https://accounts.ente.io',
  clientPackage: 'io.ente.auth.raycast',
};

const production: Environment = {
  apiUrl: 'https://api.ente.io',
  accountsUrl: 'https://accounts.ente.io',
  clientPackage: 'io.ente.auth.raycast',
};

export const environment: Environment = process.env.NODE_ENV === 'production' ? production : development; 