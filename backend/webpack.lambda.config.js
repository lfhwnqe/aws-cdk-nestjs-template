const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'production',
  target: 'node',
  context: __dirname,
  entry: './src/lambda.ts',
  output: {
    // 输出到仓库根目录的 lambda-package，保持现有部署脚本兼容
    path: path.resolve(__dirname, '../lambda-package'),
    filename: 'lambda.js',
    libraryTarget: 'commonjs2',
  },
  resolve: {
    extensions: ['.ts', '.js'],
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@nestjs/microservices': false,
      '@nestjs/websockets/socket-module': false,
      '@nestjs/websockets': false,
    },
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: {
          loader: 'ts-loader',
          options: {
            transpileOnly: true,
            configFile: path.resolve(__dirname, 'tsconfig.lambda.json'),
          },
        },
        exclude: /node_modules/,
      },
    ],
  },
  externals: [/^swagger-ui-dist(\/.*)?$/],
  plugins: [
    new webpack.IgnorePlugin({ resourceRegExp: /^@nestjs\/microservices$/ }),
    new webpack.IgnorePlugin({ resourceRegExp: /^@nestjs\/websockets$/ }),
    new webpack.IgnorePlugin({ resourceRegExp: /^@nestjs\/websockets\/socket-module$/ }),
    new webpack.IgnorePlugin({ resourceRegExp: /^class-transformer\/storage$/ }),
  ],
};
