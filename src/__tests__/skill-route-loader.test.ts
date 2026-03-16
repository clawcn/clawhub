import { beforeEach, describe, expect, it, vi } from 'vitest'

const fetchSkillPageDataMock = vi.fn()

vi.mock('../convex/client', () => ({
  convex: {},
  convexHttp: {},
}))

vi.mock('@tanstack/react-router', () => ({
  createFileRoute:
    () =>
    (config: {
      loader?: (args: { params: { owner: string; slug: string } }) => Promise<unknown>
      component?: unknown
      head?: unknown
    }) => ({ __config: config }),
  redirect: (options: unknown) => ({ redirect: options }),
}))

vi.mock('../lib/skillPage', () => ({
  fetchSkillPageData: (...args: unknown[]) => fetchSkillPageDataMock(...args),
}))

import { Route } from '../routes/$owner/$slug'

async function runLoader(params: { owner: string; slug: string }) {
  const route = Route as unknown as {
    __config: {
      loader?: (args: { params: { owner: string; slug: string } }) => Promise<unknown>
    }
  }
  const loader = route.__config.loader as (args: {
    params: { owner: string; slug: string }
  }) => Promise<unknown>

  try {
    return await loader({ params })
  } catch (error) {
    return error
  }
}

describe('skill route loader', () => {
  beforeEach(() => {
    fetchSkillPageDataMock.mockReset()
  })

  it('redirects to the canonical owner and slug from loader data', async () => {
    fetchSkillPageDataMock.mockResolvedValue({
      owner: 'steipete',
      displayName: 'Weather',
      summary: 'Get current weather.',
      version: '1.0.0',
      initialData: {
        result: {
          resolvedSlug: 'weather-pro',
          skill: {
            _id: 'skills:1',
            slug: 'weather-pro',
            displayName: 'Weather',
            summary: 'Get current weather.',
            ownerUserId: 'users:1',
            tags: {},
            badges: {},
            stats: {},
            createdAt: 0,
            updatedAt: 0,
            _creationTime: 0,
          },
          latestVersion: null,
          owner: {
            _id: 'users:1',
            _creationTime: 0,
            handle: 'steipete',
            name: 'Peter',
          },
          forkOf: null,
          canonical: null,
        },
        readme: '# Weather',
        readmeError: null,
      },
    })

    expect(await runLoader({ owner: 'legacy-owner', slug: 'weather' })).toEqual({
      redirect: {
        to: '/$owner/$slug',
        params: { owner: 'steipete', slug: 'weather-pro' },
        replace: true,
      },
    })
  })

  it('returns initial page data when the route is already canonical', async () => {
    fetchSkillPageDataMock.mockResolvedValue({
      owner: 'steipete',
      displayName: 'Weather',
      summary: 'Get current weather.',
      version: '1.0.0',
      initialData: {
        result: {
          resolvedSlug: 'weather',
          skill: {
            _id: 'skills:1',
            slug: 'weather',
            displayName: 'Weather',
            summary: 'Get current weather.',
            ownerUserId: 'users:1',
            tags: {},
            badges: {},
            stats: {},
            createdAt: 0,
            updatedAt: 0,
            _creationTime: 0,
          },
          latestVersion: null,
          owner: {
            _id: 'users:1',
            _creationTime: 0,
            handle: 'steipete',
            name: 'Peter',
          },
          forkOf: null,
          canonical: null,
        },
        readme: '# Weather',
        readmeError: null,
      },
    })

    await expect(runLoader({ owner: 'steipete', slug: 'weather' })).resolves.toEqual({
      owner: 'steipete',
      displayName: 'Weather',
      summary: 'Get current weather.',
      version: '1.0.0',
      initialData: expect.objectContaining({
        readme: '# Weather',
      }),
    })
  })
})
