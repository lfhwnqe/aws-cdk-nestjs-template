import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY, Role } from '../../common/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    if (!user) return false;

    const claims = user.claims || user;
    const groups: string[] =
      (claims['cognito:groups'] as string[]) || user.groups || [];
    const roleClaim = claims['custom:role'] || claims['role'] || user.role;

    const roleSet = new Set<string>(
      [
        ...groups,
        ...(Array.isArray(roleClaim)
          ? (roleClaim as string[])
          : roleClaim
            ? [String(roleClaim)]
            : []),
      ].map((v) => String(v)),
    );

    return requiredRoles.some((role) => roleSet.has(role));
  }
}
