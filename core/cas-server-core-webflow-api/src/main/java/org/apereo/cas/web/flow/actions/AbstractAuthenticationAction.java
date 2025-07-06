package org.apereo.cas.web.flow.actions;

import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.authentication.adaptive.UnauthorizedAuthenticationException;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.HashMap;

/**
 * This is {@link AbstractAuthenticationAction}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Slf4j
public abstract class AbstractAuthenticationAction extends BaseCasWebflowAction {

    private final CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver;

    private final CasWebflowEventResolver serviceTicketRequestWebflowEventResolver;

    private final AdaptiveAuthenticationPolicy adaptiveAuthenticationPolicy;

    // 事件处理核心 (doExecuteInternal)
    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) throws Throwable {
        // 1、自适应策略检查
        if (!evaluateAdaptiveAuthenticationPolicy(requestContext)) {
            val agent = WebUtils.getHttpServletRequestUserAgentFromRequestContext(requestContext);
            val geoLocation = WebUtils.getHttpServletRequestGeoLocationFromRequestContext(requestContext);

            val msg = "Adaptive authentication policy does not allow this request for " + agent + " and " + geoLocation;
            LOGGER.warn(msg);
            val map = CollectionUtils.<String, Throwable>wrap(UnauthorizedAuthenticationException.class.getSimpleName(),
                new UnauthorizedAuthenticationException(msg));
            // 构建认证异常对象
            val error = new AuthenticationException(msg, map, new HashMap<>());
            // 创建失败事件
            val event = new Event(this, CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE,
                new LocalAttributeMap<>(CasWebflowConstants.TRANSITION_ID_ERROR, error));
            fireEventHooks(event, requestContext);
            return event;
        }

        // 2. 先尝试服务票据解析（可能已有有效会话）
        val serviceTicketEvent = serviceTicketRequestWebflowEventResolver.resolveSingle(requestContext);
        if (serviceTicketEvent != null) {
            fireEventHooks(serviceTicketEvent, requestContext);
            return serviceTicketEvent;
        }

        // 3. 需要完整认证时，返回认证成功或失败事件
        val finalEvent = initialAuthenticationAttemptWebflowEventResolver.resolveSingle(requestContext);

        // 4、事件钩子机制
        fireEventHooks(finalEvent, requestContext);
        return finalEvent;
    }

    // 自适应策略检查 (evaluateAdaptiveAuthenticationPolicy)
    // 收集数据：用户代理(User-Agent) + 地理位置(GeoIP)
    // 策略决策：如：
    //  来自陌生地区的登录尝试
    //  非常用设备的访问
    // 拦截场景：返回false时直接阻断认证流程
    protected boolean evaluateAdaptiveAuthenticationPolicy(final RequestContext requestContext) throws Throwable {
        val agent = WebUtils.getHttpServletRequestUserAgentFromRequestContext(requestContext);
        val geoLocation = WebUtils.getHttpServletRequestGeoLocationFromRequestContext(requestContext);
        return adaptiveAuthenticationPolicy.isAuthenticationRequestAllowed(requestContext, agent, geoLocation);
    }

    // 事件钩子机制 (fireEventHooks)
    protected Event fireEventHooks(final Event event, final RequestContext ctx) {
        val id = event.getId();
        if (id.equals(CasWebflowConstants.TRANSITION_ID_ERROR) || id.equals(CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE)) {
            onError(ctx);
        }
        if (id.equals(CasWebflowConstants.TRANSITION_ID_WARN)) {
            onWarn(ctx);
        }
        if (id.equals(CasWebflowConstants.TRANSITION_ID_SUCCESS)) {
            onSuccess(ctx);
        }
        return event;
    }

    protected void onWarn(final RequestContext context) {
    }

    protected void onSuccess(final RequestContext context) {
    }

    protected void onError(final RequestContext context) {
    }
}
