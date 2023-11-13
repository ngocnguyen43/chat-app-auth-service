module.exports = {
  apps: [
    {
      name: 'app1',
      script: './app.js',
      deploy: {
        production: {
          key: '/path/to/key.pem', // path to the private key to authenticate
          user: '<server-user>', // user used to authenticate, if its AWS than ec2-user
          host: '<server-ip>', // where to connect
          ref: 'origin/master',
          repo: '<git-repo-link>',
          path: '<place-where-to-check-out>',
          'post-deploy': 'pm2 startOrRestart ecosystem.config.js --env  production',
        },
      },
    },
  ],
};
