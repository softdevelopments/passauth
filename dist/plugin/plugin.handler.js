export const pluginInit = (plugins, passauthHandler) => {
    const pluginsCollection = plugins.reduce((acc, plugin) => {
        acc[plugin.name] = {
            handler: plugin.handlerInit({ passauthHandler, plugins: acc }),
        };
        return acc;
    }, {});
    return pluginsCollection;
};
//# sourceMappingURL=plugin.handler.js.map