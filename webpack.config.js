const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
    mode: 'production',
    entry: {
        bundle: ['./frontend/src/chat.js', './frontend/src/styles.css'],
        mfa: ['./frontend/src/mfa.js', './frontend/src/mfa.css'],
        account: ['./frontend/src/account.js']
    },
    output: {
        filename: '[name].js',
        path: path.resolve(__dirname, 'app/static/dist'),
        clean: true
    },
    module: {
        rules: [
            {
                test: /\.css$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    'css-loader'
                ]
            },
            {
                test: /\.(png|svg|jpg|jpeg|gif)$/i,
                type: 'asset/resource'
            }
        ]
    },
    plugins: [
        new MiniCssExtractPlugin({
            filename: '[name].css'
        })
    ]
};