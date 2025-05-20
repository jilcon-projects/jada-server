"""
Custom pagination classes for BuildCalc API
"""

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from collections import OrderedDict


class CustomPagination(PageNumberPagination):
    """
    Custom pagination class that provides standardized pagination response
    """
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'
    
    def get_paginated_response(self, data):
        """
        Return a paginated style response with standard format
        """
        return Response(OrderedDict([
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('page_size', self.page_size),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('results', data)
        ]))
    
    def get_page_size(self, request):
        """
        Determine the page size to use for pagination
        """
        if self.page_size_query_param:
            try:
                page_size = min(
                    int(request.query_params[self.page_size_query_param]),
                    self.max_page_size
                )
                return page_size
            except (KeyError, ValueError):
                pass
        
        return self.page_size


class LargeResultsSetPagination(PageNumberPagination):
    """
    Pagination for large result sets
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200
    page_query_param = 'page'
    
    def get_paginated_response(self, data):
        """
        Return paginated response for large datasets
        """
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'page_number': self.page.number,
            'page_size': len(data),
            'results': data
        })


class SmallResultsSetPagination(PageNumberPagination):
    """
    Pagination for small result sets
    """
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 50
    page_query_param = 'page'
    
    def get_paginated_response(self, data):
        """
        Return paginated response for small datasets
        """
        return Response({
            'count': self.page.paginator.count,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data
        })


class StandardPagination(PageNumberPagination):
    """
    Standard pagination following the BuildCalc response format
    """
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'
    
    def get_paginated_response(self, data):
        """
        Return response in BuildCalc standard format
        """
        return Response({
            'success': True,
            'message': 'Data retrieved successfully',
            'code': 'data_retrieved',
            'data': {
                'results': data,
                'pagination': {
                    'count': self.page.paginator.count,
                    'next': self.get_next_link(),
                    'previous': self.get_previous_link(),
                    'page_size': len(data),
                    'total_pages': self.page.paginator.num_pages,
                    'current_page': self.page.number,
                    'has_next': self.page.has_next(),
                    'has_previous': self.page.has_previous(),
                }
            }
        })